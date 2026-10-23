#import "anisette.h"

// Uses an independent, persistent v3 identity; never receives account credentials.
void ALTFetchRemoteAnisetteData(void (^ _Nonnull completion)(ALTAnisetteData * _Nullable, NSError * _Nullable));
void ALTResynchronizeRemoteAnisetteData(NSString * _Nonnull sim,
    void (^ _Nonnull completion)(ALTAnisetteData * _Nullable, NSError * _Nullable));
