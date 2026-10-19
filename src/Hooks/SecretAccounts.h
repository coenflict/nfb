//
//  SecretAccounts.h
//  NeoFreeBird
//

#import <UIKit/UIKit.h>

// Every native account, hidden ones included. Use this instead of
// -[TFNTwitter accounts] when looking an account up by ID.
NSArray* BHTAllNativeAccounts(void);

// Shows the hidden account switcher anchored to `sourceView`.
void BHTPresentSecretSwitcher(UIView* sourceView);
