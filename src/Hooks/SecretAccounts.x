//
//  SecretAccounts.x
//  NeoFreeBird
//
//  A second, hidden account switcher. Accounts marked secret are filtered out
//  of the native account list, so the regular switcher never sees them, and
//  the secret switcher only ever lists them. It opens with a two-finger long
//  press on the home top bar (Settings.x), next to the one-finger NFB menu.
//

#import <stdatomic.h>
#import "HookHelpers.h"
#import "SecretAccounts.h"

static NSString* const kSecretAccountIDsKey = @"bh_secret_account_ids";

static NSSet<NSString*>* secretIDs;

// While > 0, -accounts returns the full list. Raised around our own lookups
// and around the app's own account persistence/mutation paths so a filtered
// list can never be written back over the real one.
static atomic_int bypassDepth = 0;

static void loadSecretIDs(void) {
    NSArray* ids = [[NSUserDefaults standardUserDefaults] arrayForKey:kSecretAccountIDsKey];
    secretIDs = ids.count ? [NSSet setWithArray:ids] : nil;
}

static id sendGetter(id target, SEL selector) {
    if (!target || ![target respondsToSelector:selector]) {
        return nil;
    }
    return ((id (*)(id, SEL))objc_msgSend)(target, selector);
}

static NSString* accountIDString(id account) {
    if (!account || ![account respondsToSelector:@selector(userID)]) {
        return nil;
    }
    Method method = class_getInstanceMethod([account class], @selector(userID));
    char returnType[8] = {0};
    if (method) {
        method_getReturnType(method, returnType, sizeof(returnType));
    }
    if (returnType[0] == '@') {
        id value = sendGetter(account, @selector(userID));
        if ([value isKindOfClass:[NSString class]]) {
            return value;
        }
        return [value respondsToSelector:@selector(stringValue)] ? [value stringValue] : nil;
    }
    long long uid = ((long long (*)(id, SEL))objc_msgSend)(account, @selector(userID));
    return uid ? [@(uid) stringValue] : nil;
}

static NSString* accountHandle(id account) {
    NSString* name = sendGetter(account, @selector(username));
    if (![name isKindOfClass:[NSString class]] || name.length == 0) {
        name = sendGetter(account, @selector(displayUsername));
    }
    if ([name isKindOfClass:[NSString class]] && name.length) {
        return [name hasPrefix:@"@"] ? name : [@"@" stringByAppendingString:name];
    }
    return accountIDString(account) ?: @"?";
}

static id currentNativeAccount(void) {
    id host = sendGetter(objc_getClass("T1HostViewController"), @selector(sharedHostViewController));
    return sendGetter(host, @selector(currentAccount));
}

NSArray* BHTAllNativeAccounts(void) {
    NSArray* accounts = nil;
    atomic_fetch_add(&bypassDepth, 1);
    @try {
        id shared = sendGetter(objc_getClass("TFNTwitter"), @selector(sharedTwitter));
        accounts = sendGetter(shared, @selector(accounts));
    } @catch (__unused NSException* exception) {
    }
    atomic_fetch_sub(&bypassDepth, 1);
    return [accounts isKindOfClass:[NSArray class]] ? accounts : @[];
}

#pragma mark - Bypass wrapping

static BOOL isRegisterSizedType(const char* type) {
    while (*type && strchr("rnNoORV", *type)) {
        type++;
    }
    return *type && strchr("v@#:*^BcCiIsSlLqQ", *type) != NULL;
}

// Wraps a method so the account filter is off for its duration. Only plain
// signatures (no args or one register-sized arg, register-sized return) are
// touched, which lets one trampoline forward any of them unchanged.
static void wrapWithBypass(Method method) {
    unsigned argc = method_getNumberOfArguments(method);
    if (argc > 3) {
        return;
    }
    char type[16] = {0};
    method_getReturnType(method, type, sizeof(type));
    if (!isRegisterSizedType(type)) {
        return;
    }
    if (argc == 3) {
        method_getArgumentType(method, 2, type, sizeof(type));
        if (!isRegisterSizedType(type)) {
            return;
        }
    }

    IMP orig = method_getImplementation(method);
    SEL sel = method_getName(method);
    IMP replacement;
    if (argc == 2) {
        replacement = imp_implementationWithBlock(^void*(__unsafe_unretained id target) {
            atomic_fetch_add(&bypassDepth, 1);
            @try {
                return ((void* (*)(id, SEL))orig)(target, sel);
            } @finally {
                atomic_fetch_sub(&bypassDepth, 1);
            }
        });
    } else {
        replacement = imp_implementationWithBlock(^void*(__unsafe_unretained id target, void* arg) {
            atomic_fetch_add(&bypassDepth, 1);
            @try {
                return ((void* (*)(id, SEL, void*))orig)(target, sel, arg);
            } @finally {
                atomic_fetch_sub(&bypassDepth, 1);
            }
        });
    }
    method_setImplementation(method, replacement);
}

static BOOL selectorMutatesAccounts(SEL sel) {
    NSString* name = NSStringFromSelector(sel).lowercaseString;
    if ([name isEqualToString:@"accounts"] || [name hasPrefix:@"."] || [name containsString:@"dealloc"]) {
        return NO;
    }
    static NSArray<NSString*>* fragments;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        fragments = @[ @"save", @"persist", @"archive", @"encode", @"setaccounts", @"addaccount",
                       @"removeaccount", @"deleteaccount", @"logout", @"replace", @"migrat",
                       @"purge", @"clean", @"sync" ];
    });
    for (NSString* fragment in fragments) {
        if ([name containsString:fragment]) {
            return YES;
        }
    }
    return NO;
}

static NSArray* filteredAccounts(NSArray* accounts);

static void installHooksOnClass(Class cls, BOOL filterAccountsGetter) {
    Class targets[2] = {cls, object_getClass(cls)};
    for (int i = 0; i < 2; i++) {
        unsigned count = 0;
        Method* methods = class_copyMethodList(targets[i], &count);
        for (unsigned j = 0; j < count; j++) {
            SEL sel = method_getName(methods[j]);
            if (selectorMutatesAccounts(sel)) {
                wrapWithBypass(methods[j]);
            } else if (filterAccountsGetter && i == 0 && sel == @selector(accounts)) {
                IMP orig = method_getImplementation(methods[j]);
                method_setImplementation(methods[j], imp_implementationWithBlock(^id(__unsafe_unretained id target) {
                    return filteredAccounts(((id (*)(id, SEL))orig)(target, @selector(accounts)));
                }));
            }
        }
        free(methods);
    }
}

// The account service is only reachable through a live TFNTwitter, so its
// hooks go in the first time filtering actually matters.
static void installServiceHooks(void) {
    static BOOL installed = NO;
    if (installed) {
        return;
    }
    installed = YES;
    id shared = sendGetter(objc_getClass("TFNTwitter"), @selector(sharedTwitter));
    id service = sendGetter(shared, @selector(accountService));
    Class serviceClass = object_getClass(service);
    if (service && serviceClass != objc_getClass("TFNTwitter")) {
        installHooksOnClass(serviceClass, YES);
    }
}

#pragma mark - Filtering

static NSArray* filteredAccounts(NSArray* accounts) {
    if (secretIDs.count == 0 || ![NSThread isMainThread] || atomic_load(&bypassDepth) > 0 ||
        ![accounts isKindOfClass:[NSArray class]] || accounts.count < 2) {
        return accounts;
    }

    atomic_fetch_add(&bypassDepth, 1);
    NSArray* result = accounts;
    @try {
        installServiceHooks();
        // Until launch has settled on a current account, leave the list whole so
        // restoring the last-used account still works.
        NSString* currentID = accountIDString(currentNativeAccount());
        if (currentID) {
            NSMutableArray* visible = [NSMutableArray arrayWithCapacity:accounts.count];
            for (id account in accounts) {
                NSString* accountID = accountIDString(account);
                // The active account always stays, so the app never thinks it vanished.
                if (!accountID || ![secretIDs containsObject:accountID] ||
                    [accountID isEqualToString:currentID]) {
                    [visible addObject:account];
                }
            }
            if (visible.count) {
                result = [visible copy];
            }
        }
    } @catch (__unused NSException* exception) {
    }
    atomic_fetch_sub(&bypassDepth, 1);
    return result;
}

%hook TFNTwitter

- (NSArray*)accounts {
    NSArray* accounts = %orig;
    return filteredAccounts(accounts);
}

%end

#pragma mark - Switcher UI

static void postAccountsChanged(void) {
    id shared = sendGetter(objc_getClass("TFNTwitter"), @selector(sharedTwitter));
    id name = sendGetter(objc_getClass("TFSAccountNotification"), @selector(TFSAccountsDidChange));
    if ([name isKindOfClass:[NSString class]]) {
        [[NSNotificationCenter defaultCenter] postNotificationName:name object:shared userInfo:nil];
    }
}

static void setAccountSecret(NSString* accountID, BOOL secret) {
    NSMutableSet* ids = secretIDs ? [secretIDs mutableCopy] : [NSMutableSet set];
    if (secret) {
        [ids addObject:accountID];
    } else {
        [ids removeObject:accountID];
    }
    [[NSUserDefaults standardUserDefaults] setObject:ids.allObjects forKey:kSecretAccountIDsKey];
    loadSecretIDs();
    postAccountsChanged();
}

static void switchToAccount(id account) {
    id host = sendGetter(objc_getClass("T1HostViewController"), @selector(sharedHostViewController));
    if ([host respondsToSelector:@selector(viewAccount:animated:)]) {
        @try {
            ((void (*)(id, SEL, id, BOOL))objc_msgSend)(host, @selector(viewAccount:animated:), account, YES);
        } @catch (__unused NSException* exception) {
        }
    }
}

static UIViewController* topViewController(UIWindow* window) {
    UIViewController* top = window.rootViewController;
    while (top.presentedViewController && !top.presentedViewController.isBeingDismissed) {
        top = top.presentedViewController;
    }
    return top;
}

static void presentSheet(UIAlertController* sheet, UIView* sourceView) {
    UIViewController* top = topViewController(sourceView.window);
    if (!top) {
        return;
    }
    sheet.popoverPresentationController.sourceView = sourceView;
    sheet.popoverPresentationController.sourceRect = sourceView.bounds;
    [top presentViewController:sheet animated:YES completion:nil];
}

static void presentSecretManager(UIView* sourceView) {
    UIAlertController* sheet =
        [UIAlertController alertControllerWithTitle:@"Hidden accounts"
                                            message:@"Hidden accounts only appear here."
                                     preferredStyle:UIAlertControllerStyleActionSheet];
    for (id account in BHTAllNativeAccounts()) {
        NSString* accountID = accountIDString(account);
        if (!accountID) {
            continue;
        }
        BOOL secret = [secretIDs containsObject:accountID];
        NSString* title = [NSString stringWithFormat:@"%@ %@", secret ? @"Unhide" : @"Hide", accountHandle(account)];
        [sheet addAction:[UIAlertAction actionWithTitle:title
                                                  style:secret ? UIAlertActionStyleDefault
                                                               : UIAlertActionStyleDestructive
                                                handler:^(__unused UIAlertAction* action) {
                                                    setAccountSecret(accountID, !secret);
                                                }]];
    }
    [sheet addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
    presentSheet(sheet, sourceView);
}

void BHTPresentSecretSwitcher(UIView* sourceView) {
    NSString* currentID = accountIDString(currentNativeAccount());
    NSMutableArray* secretAccounts = [NSMutableArray array];
    for (id account in BHTAllNativeAccounts()) {
        NSString* accountID = accountIDString(account);
        if (accountID && [secretIDs containsObject:accountID]) {
            [secretAccounts addObject:account];
        }
    }

    UIAlertController* sheet =
        [UIAlertController alertControllerWithTitle:nil
                                            message:secretAccounts.count ? nil : @"No hidden accounts yet."
                                     preferredStyle:UIAlertControllerStyleActionSheet];
    for (id account in secretAccounts) {
        BOOL isCurrent = [accountIDString(account) isEqualToString:currentID];
        NSString* title = isCurrent ? [accountHandle(account) stringByAppendingString:@"  ✓"] : accountHandle(account);
        UIAlertAction* action = [UIAlertAction actionWithTitle:title
                                                         style:UIAlertActionStyleDefault
                                                       handler:^(__unused UIAlertAction* a) {
                                                           if (!isCurrent) {
                                                               switchToAccount(account);
                                                           }
                                                       }];
        [sheet addAction:action];
    }
    __weak UIView* weakSource = sourceView;
    [sheet addAction:[UIAlertAction actionWithTitle:@"Manage…"
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction* a) {
                                                UIView* source = weakSource;
                                                if (source.window) {
                                                    presentSecretManager(source);
                                                }
                                            }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Cancel" style:UIAlertActionStyleCancel handler:nil]];
    presentSheet(sheet, sourceView);
}

%ctor {
    loadSecretIDs();
    Class twitterClass = objc_getClass("TFNTwitter");
    if (twitterClass) {
        installHooksOnClass(twitterClass, NO);
    }
    %init;
}
