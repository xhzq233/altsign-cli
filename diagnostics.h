#import <Foundation/Foundation.h>

// Stages must be developer-defined labels, never account data or error descriptions.
void ALTDiagnosticsStart(NSString *command);
void ALTDiagnosticsEvent(NSString *stage, NSInteger code);
void ALTDiagnosticsHTTP(NSString *stage, NSURLResponse *response, NSError *error);
void ALTDiagnosticsFinish(int exitCode);
NSString *ALTDiagnosticsPath(void);
