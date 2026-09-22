#define main OriginalMain
#include "../main.mm"
#undef main
#import <objc/runtime.h>
#include <assert.h>

static NSArray<ALTTeam *> *availableTeams;
static ALTTeam *queriedTeam;
static NSInteger certificateCalls, appIDCalls;
static BOOL failCertificates;

@interface ALTAppleAPI (TeamTest)
- (void)testTeams:(ALTAccount *)account session:(ALTAppleAPISession *)session completionHandler:(void (^)(NSArray<ALTTeam *> *, NSError *))completion;
- (void)testCertificates:(ALTTeam *)team session:(ALTAppleAPISession *)session completionHandler:(void (^)(NSArray<ALTCertificate *> *, NSError *))completion;
- (void)testAppIDs:(ALTTeam *)team session:(ALTAppleAPISession *)session completionHandler:(void (^)(NSArray<ALTAppID *> *, NSError *))completion;
@end
@implementation ALTAppleAPI (TeamTest)
- (void)testTeams:(ALTAccount *)account session:(ALTAppleAPISession *)session completionHandler:(void (^)(NSArray<ALTTeam *> *, NSError *))completion {
    completion(availableTeams, nil);
}
- (void)testCertificates:(ALTTeam *)team session:(ALTAppleAPISession *)session completionHandler:(void (^)(NSArray<ALTCertificate *> *, NSError *))completion {
    queriedTeam = team;
    certificateCalls++;
    completion(@[], failCertificates ? [NSError errorWithDomain:@"test" code:17 userInfo:nil] : nil);
}
- (void)testAppIDs:(ALTTeam *)team session:(ALTAppleAPISession *)session completionHandler:(void (^)(NSArray<ALTAppID *> *, NSError *))completion {
    assert(team == queriedTeam);
    appIDCalls++;
    completion(@[], nil);
}
@end
@interface ALTAnisetteData (TeamTest)
+ (void)testAnisette:(void (^)(ALTAnisetteData *, NSError *))completion;
@end
@implementation ALTAnisetteData (TeamTest)
+ (void)testAnisette:(void (^)(ALTAnisetteData *, NSError *))completion { completion([ALTAnisetteData new], nil); }
@end

static void swap(SEL original, SEL replacement) {
    method_exchangeImplementations(class_getInstanceMethod(ALTAppleAPI.class, original), class_getInstanceMethod(ALTAppleAPI.class, replacement));
}
static ALTTeam *makeTeam(NSString *identifier) {
    ALTTeam *team = [ALTTeam new]; team.identifier = identifier; team.name = @"Test team"; team.type = @"Individual"; return team;
}
int main(void) {
    @autoreleasepool {
        ALTTeam *a = makeTeam(@"TEAM_A"), *b = makeTeam(@"TEAM_B");
        assert(selectTeam(@[a], nil) == a);
        assert(selectTeam(@[a, b], b.identifier) == b);
        assert(selectTeam(@[b, a], b.identifier) == b);
        assert(selectTeam(@[a, b], nil) == nil);
        assert(selectTeam(@[a], b.identifier) == nil);
        NSString *error = nil;
        assert(validateCommandOptions(@[@"cli", @"list", @"--team-id", @"TEAM_B"], @"list", &error));
        assert(!validateCommandOptions(@[@"cli", @"list", @"--team-id", @""], @"list", &error));
        assert(!validateCommandOptions(@[@"cli", @"list", @"--team-id", @"TEAM_A", @"--team-id", @"TEAM_B"], @"list", &error));
        assert(!validateCommandOptions(@[@"cli", @"sign", @"--team-id"], @"sign", &error));

        Method anisette = class_getClassMethod(ALTAnisetteData.class, @selector(fetchAnisetteDataWithCompletion:));
        Method replacement = class_getClassMethod(ALTAnisetteData.class, @selector(testAnisette:));
        method_exchangeImplementations(anisette, replacement);
        swap(@selector(fetchTeamsForAccount:session:completionHandler:), @selector(testTeams:session:completionHandler:));
        swap(@selector(fetchCertificatesForTeam:session:completionHandler:), @selector(testCertificates:session:completionHandler:));
        swap(@selector(fetchAppIDsForTeam:session:completionHandler:), @selector(testAppIDs:session:completionHandler:));
        ALTAppleAPISession *session = [[ALTAppleAPISession alloc] initWithDSID:@"test" authToken:@"test-token" anisetteData:[ALTAnisetteData new]];
        session.expirationDate = [NSDate dateWithTimeIntervalSinceNow:3600];
        assert([session saveForAppleID:@"test@example.invalid"]);
        availableTeams = @[a,b];
        assert(performList(@"test@example.invalid", nil, nil));
        assert(certificateCalls == 0 && appIDCalls == 0);
        assert(performList(@"test@example.invalid", nil, b.identifier));
        assert(queriedTeam == b && certificateCalls == 1 && appIDCalls == 1);
        assert(!performList(@"test@example.invalid", nil, @"UNKNOWN"));
        assert(certificateCalls == 1 && appIDCalls == 1);
        certificateCalls = 0; failCertificates = YES;
        assert(!performSign(@"test@example.invalid", nil, @"test", @"test.ipa", @"output.ipa", @[], nil));
        assert(certificateCalls == 0); // Stops before any certificate/device mutation is possible.
        assert(!performSign(@"test@example.invalid", nil, @"test", @"test.ipa", @"output.ipa", @[], @"UNKNOWN"));
        assert(certificateCalls == 0);
        assert(!performSign(@"test@example.invalid", nil, @"test", @"test.ipa", @"output.ipa", @[], b.identifier));
        assert(certificateCalls == 1 && queriedTeam == b);
        availableTeams = @[a];
        assert(!performSign(@"test@example.invalid", nil, @"test", @"test.ipa", @"output.ipa", @[], nil));
        assert(certificateCalls == 2 && queriedTeam == a);
        failCertificates = NO;
        assert(performList(@"test@example.invalid", nil, nil));
        assert(queriedTeam == a && appIDCalls == 2);
        availableTeams = @[];
        assert(!performList(@"test@example.invalid", nil, nil));
        assert(certificateCalls == 3);
        method_exchangeImplementations(anisette, replacement);
        swap(@selector(fetchTeamsForAccount:session:completionHandler:), @selector(testTeams:session:completionHandler:));
        swap(@selector(fetchCertificatesForTeam:session:completionHandler:), @selector(testCertificates:session:completionHandler:));
        swap(@selector(fetchAppIDsForTeam:session:completionHandler:), @selector(testAppIDs:session:completionHandler:));
        puts("[altsign-test] Team selection and pre-mutation rejection passed");
    }
}
