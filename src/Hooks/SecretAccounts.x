//
//  SecretAccounts.x
//  NeoFreeBird
//
//  A second, hidden account switcher. Accounts marked secret are filtered out
//  of the native account list, so the regular switcher never sees them, and
//  the secret switcher only ever lists them. It opens with a two-finger long
//  press on the home top bar (Settings.x), next to the one-finger NFB menu.
//  It is also the only way into a hidden account: any other switch to one is
//  dropped, launch opens the unhidden account instead, the sidebar never shows
//  them, and after two idle minutes the app hands back to the unhidden account.
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

#pragma mark - Switch guard

static NSString* const kReturnAccountIDKey = @"bh_secret_return_account_id";

// Idle time (touches only, background included) after which a hidden account
// hands back to the unhidden one.
static const CFTimeInterval kHiddenIdleTimeout = 120;

// Set only by the secret switcher, for the account it is switching to.
static NSString* approvedSwitchID;

// The account the guard last let the host show. nil until launch opens one.
static NSString* shownAccountID;

static CFAbsoluteTime lastActivity;
static BOOL returningToUnhidden;
static UIWindow* shieldWindow;

static BOOL isSecretID(NSString* accountID) {
    return accountID && [secretIDs containsObject:accountID];
}

static BOOL isSecretAccount(id account) {
    return isSecretID(accountIDString(account));
}

// The unhidden account to fall back to: the last one used, else the first.
static id returnAccount(void) {
    NSString* savedID = [[NSUserDefaults standardUserDefaults] stringForKey:kReturnAccountIDKey];
    id fallback = nil;
    for (id account in BHTAllNativeAccounts()) {
        NSString* accountID = accountIDString(account);
        if (!accountID || isSecretID(accountID)) {
            continue;
        }
        if ([accountID isEqualToString:savedID]) {
            return account;
        }
        fallback = fallback ?: account;
    }
    return fallback;
}

static id showAccount(id account) {
    NSString* accountID = accountIDString(account);
    shownAccountID = accountID;
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    if (accountID && !isSecretID(accountID) && ![[defaults stringForKey:kReturnAccountIDKey] isEqualToString:accountID]) {
        [defaults setObject:accountID forKey:kReturnAccountIDKey];
    }
    return account;
}

// Hidden accounts can still be reached through routes that don't use the
// filtered list (the sidebar avatars, notifications, links), so every switch
// goes through here. Returns the account the host should actually show, or
// nil to drop the switch.
static id resolveSwitchTarget(id account) {
    NSString* targetID = accountIDString(account);
    if (!targetID || !isSecretID(targetID) || [targetID isEqualToString:approvedSwitchID] ||
        [targetID isEqualToString:shownAccountID]) {
        return showAccount(account);
    }
    // Launch is restoring a hidden account: open the unhidden one instead,
    // before anything of the hidden account's is built.
    if (!shownAccountID || !currentNativeAccount()) {
        return showAccount(returnAccount() ?: account);
    }
    for (id other in BHTAllNativeAccounts()) {
        if ([accountIDString(other) isEqualToString:shownAccountID]) {
            return nil;
        }
    }
    // The shown account was just logged out, so the app has to land somewhere.
    return showAccount(returnAccount() ?: account);
}

static void requestSwitch(id account, BOOL animated) {
    id host = sendGetter(objc_getClass("T1HostViewController"), @selector(sharedHostViewController));
    if (account && [host respondsToSelector:@selector(viewAccount:animated:)]) {
        @try {
            ((void (*)(id, SEL, id, BOOL))objc_msgSend)(host, @selector(viewAccount:animated:), account, animated);
        } @catch (__unused NSException* exception) {
        }
    }
}

// An opaque window over the app, so nothing of a hidden account is visible in
// the app switcher or while handing back to the unhidden account.
static void showShield(void) {
    if (shieldWindow) {
        return;
    }
    UIWindowScene* scene = nil;
    for (UIScene* candidate in UIApplication.sharedApplication.connectedScenes) {
        if ([candidate isKindOfClass:[UIWindowScene class]]) {
            scene = (UIWindowScene*)candidate;
            break;
        }
    }
    if (!scene) {
        return;
    }
    shieldWindow = [[UIWindow alloc] initWithWindowScene:scene];
    shieldWindow.windowLevel = UIWindowLevelAlert + 100;
    shieldWindow.rootViewController = [UIViewController new];
    shieldWindow.rootViewController.view.backgroundColor = UIColor.systemBackgroundColor;
    shieldWindow.backgroundColor = UIColor.systemBackgroundColor;
    shieldWindow.hidden = NO;
}

static void hideShield(void) {
    shieldWindow.hidden = YES;
    shieldWindow = nil;
}

// Keeps the shield up until the host really is on an unhidden account,
// re-sending the switch every couple of seconds if it hasn't landed.
static void confirmReturn(int attempt) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.25 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        id current = currentNativeAccount();
        if (current && !isSecretAccount(current)) {
            returningToUnhidden = NO;
            hideShield();
            return;
        }
        id target = returnAccount();
        if (!target) {
            returningToUnhidden = NO;
            hideShield();
            return;
        }
        if (attempt % 8 == 7) {
            requestSwitch(target, NO);
        }
        confirmReturn(attempt + 1);
    });
}

static void returnToUnhiddenAccount(void) {
    if (returningToUnhidden) {
        return;
    }
    id target = returnAccount();
    if (!target) {
        hideShield();
        return;
    }
    returningToUnhidden = YES;
    showShield();
    requestSwitch(target, NO);
    confirmReturn(0);
}

static BOOL hiddenIdleExpired(void) {
    return isSecretAccount(currentNativeAccount()) && CFAbsoluteTimeGetCurrent() - lastActivity >= kHiddenIdleTimeout;
}

static void hiddenIdleTick(void) {
    if (returningToUnhidden || UIApplication.sharedApplication.applicationState != UIApplicationStateActive) {
        return;
    }
    if (!isSecretAccount(currentNativeAccount())) {
        lastActivity = CFAbsoluteTimeGetCurrent();
    } else if (hiddenIdleExpired()) {
        returnToUnhiddenAccount();
    }
}

static void observeAppLifecycle(void) {
    NSNotificationCenter* center = [NSNotificationCenter defaultCenter];
    [center addObserverForName:UIApplicationDidEnterBackgroundNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(__unused NSNotification* note) {
                        if (isSecretAccount(currentNativeAccount())) {
                            showShield();
                        }
                    }];
    // Runs before the app refreshes anything on becoming active, so a timed
    // out hidden account is swapped out before its timeline reloads.
    [center addObserverForName:UIApplicationWillEnterForegroundNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(__unused NSNotification* note) {
                        if (hiddenIdleExpired()) {
                            returnToUnhiddenAccount();
                        } else if (!returningToUnhidden) {
                            hideShield();
                        }
                    }];
    [NSTimer scheduledTimerWithTimeInterval:5
                                    repeats:YES
                                      block:^(__unused NSTimer* timer) {
                                          hiddenIdleTick();
                                      }];
}

%hook UIApplication

- (void)sendEvent:(UIEvent*)event {
    if (event.type == UIEventTypeTouches) {
        lastActivity = CFAbsoluteTimeGetCurrent();
    }
    %orig;
}

%end

%hook T1HostViewController

- (void)setupWithAccount:(id)account {
    id target = resolveSwitchTarget(account);
    if (target || !account) {
        %orig(target);
    }
}

- (void)handleRootViewControllerSetupWithAccount:(id)account {
    id target = resolveSwitchTarget(account);
    if (target || !account) {
        %orig(target);
    }
}

- (void)viewAccount:(id)account animated:(BOOL)animated {
    id target = resolveSwitchTarget(account);
    if (target || !account) {
        %orig(target, animated);
    }
}

- (void)viewAccount:(id)account withPanelID:(long long)panelID animated:(BOOL)animated {
    id target = resolveSwitchTarget(account);
    if (target || !account) {
        %orig(target, panelID, animated);
    }
}

- (void)viewAccount:(id)account withPanelID:(long long)panelID animated:(BOOL)animated completion:(id)completion {
    id target = resolveSwitchTarget(account);
    if (target || !account) {
        %orig(target, panelID, animated, completion);
    }
}

- (void)viewAccount:(id)account
        withPanelID:(long long)panelID
     preserveModals:(BOOL)preserveModals
           animated:(BOOL)animated
         completion:(id)completion {
    id target = resolveSwitchTarget(account);
    if (target || !account) {
        %orig(target, panelID, preserveModals, animated, completion);
    }
}

- (void)viewAccount:(id)account
                 withPanelID:(long long)panelID
              preserveModals:(BOOL)preserveModals
    additionalViewController:(id)viewController
                    animated:(BOOL)animated
                  completion:(id)completion {
    id target = resolveSwitchTarget(account);
    if (target || !account) {
        %orig(target, panelID, preserveModals, viewController, animated, completion);
    }
}

%end

#pragma mark - Sidebar

static NSArray* withoutSecretAccounts(NSArray* accounts) {
    if (secretIDs.count == 0 || ![accounts isKindOfClass:[NSArray class]]) {
        return accounts;
    }
    NSIndexSet* keep = [accounts indexesOfObjectsPassingTest:^BOOL(id account, __unused NSUInteger idx, __unused BOOL* stop) {
        return !isSecretAccount(account);
    }];
    return keep.count == accounts.count ? accounts : [accounts objectsAtIndexes:keep];
}

// The sidebar's account bubbles (and their badges) come from their own list,
// so hidden accounts are taken out of it here.
%hook T1DashAccountSwitcherView

- (void)setAccounts:(NSArray*)accounts {
    %orig(withoutSecretAccounts(accounts));
}

- (void)setVisibleAccounts:(NSArray*)accounts {
    %orig(withoutSecretAccounts(accounts));
}

- (NSArray*)accountsSortedByLastActiveDate:(NSArray*)accounts {
    NSArray* sorted = %orig;
    return withoutSecretAccounts(sorted);
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
    NSString* accountID = accountIDString(account);
    approvedSwitchID = accountID;
    lastActivity = CFAbsoluteTimeGetCurrent();
    requestSwitch(account, YES);
    // Once the switch has landed the account is the shown one, which the guard
    // allows anyway, so the approval only has to outlive the transition.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(10 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        if ([approvedSwitchID isEqualToString:accountID]) {
            approvedSwitchID = nil;
        }
    });
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
    lastActivity = CFAbsoluteTimeGetCurrent();
    dispatch_async(dispatch_get_main_queue(), ^{
        observeAppLifecycle();
    });
    %init;
}
