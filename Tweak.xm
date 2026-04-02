/**
 * ============================================================================
 *  PentestTweak v3.0 — Triple-Attack (Diagnostic + Network + Storage Hook)
 * ============================================================================
 *
 *  DIAGNOSIS CONFIRMED: SectionModel / StudentModel are Pure Swift classes
 *  with Static Dispatch. They are NOT visible in the ObjC runtime at all.
 *  method_setImplementation() CANNOT hook them.
 *
 *  NEW STRATEGY — Bypass the model layer entirely:
 *
 *    Attack Vector 1: NETWORK INTERCEPTION
 *       Hook NSURLProtocol to intercept ALL API responses from the app's
 *       server and rewrite subscription flags to TRUE before the app sees them.
 *       This works regardless of Swift/ObjC because it operates at the
 *       HTTP transport layer.
 *
 *    Attack Vector 2: LOCAL STORAGE TAMPERING
 *       Hook NSUserDefaults to intercept reads of subscription-related keys
 *       and return "active" values. Also hook the setter to prevent the app
 *       from overwriting our tampered values.
 *
 *    Attack Vector 3: RUNTIME DIAGNOSTIC (enhanced)
 *       Comprehensive dump of ALL ObjC classes, search for ANY hookable
 *       entry points, enumerate loaded images, check for framework hooks.
 *
 *  WHY THIS WORKS:
 *    Even Pure Swift apps MUST use Foundation networking classes (URLSession)
 *    and storage classes (UserDefaults) which ARE ObjC-based and hookable.
 *    The data flows: Server → Network (ObjC) → Swift Parser → Swift Model → UI
 *    We intercept at the ObjC boundary BEFORE data reaches Swift code.
 *
 *  TARGET:  com.xapps.vip (v5.7)
 *  BUILD:   Pure ObjC Runtime — ZERO external dependencies
 *  DATE:    2026-04-02
 * ============================================================================
 */

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>


#pragma mark - ──────────────────────────────────────────────────────────────
#pragma mark   Configuration
#pragma mark - ──────────────────────────────────────────────────────────────

/**
 * TODO: After running the diagnostic dump, update these arrays with the
 * actual hostnames, URL patterns, and UserDefaults keys used by the app.
 *
 * Right now they contain common patterns for educational/subscription apps.
 * The diagnostic log will reveal the REAL values you need.
 */

/** Server hostnames to intercept (any response from these hosts gets modified) */
static NSArray *PT_GetTargetHosts(void) {
    return @[
        @"xapps.vip",
        @"api.xapps.vip",
        @"xappsvip.com",
        @"api.xappsvip.com",
    ];
}

/** URL path substrings that indicate subscription/user data endpoints */
static NSArray *PT_GetTargetPathPatterns(void) {
    return @[
        @"/subscription",
        @"/subscribe",
        @"/user",
        @"/profile",
        @"/me",
        @"/status",
        @"/check",
        @"/purchase",
        @"/payment",
        @"/section",
        @"/content",
    ];
}

/** UserDefaults keys that may store subscription data */
static NSArray *PT_GetTargetUserDefaultsKeys(void) {
    return @[
        @"isSubscribed",
        @"isSubscriped",
        @"subscriptionStatus",
        @"subscription_status",
        @"isPremium",
        @"isVip",
        @"isFree",
        @"userType",
        @"subscriptionExpiry",
        @"studentCanBuy",
        @"bySubscription",
        @"hasActiveSubscription",
        @"userSubscription",
        @"planType",
        @"plan",
        @"isSubscri",
    ];
}


#pragma mark - ──────────────────────────────────────────────────────────────
#pragma mark   Logging
#pragma mark - ──────────────────────────────────────────────────────────────

#define PT_LOG(fmt, ...)   NSLog(@"[PT v3][INFO] " fmt, ##__VA_ARGS__)
#define PT_ERR(fmt, ...)   NSLog(@"[PT v3][ERROR] " fmt, ##__VA_ARGS__)
#define PT_NET(fmt, ...)   NSLog(@"[PT v3][NET] " fmt, ##__VA_ARGS__)
#define PT_UDS(fmt, ...)   NSLog(@"[PT v3][UDS] " fmt, ##__VA_ARGS__)
#define PT_DIAG(fmt, ...)  NSLog(@"[PT v3][DIAG] " fmt, ##__VA_ARGS__)


#pragma mark - ══════════════════════════════════════════════════════════════
#pragma mark   ATTACK 1: Network Interception (NSURLProtocol)
#pragma mark - ══════════════════════════════════════════════════════════════

/**
 * PTNetworkInterceptor
 *
 * A custom NSURLProtocol that intercepts HTTP/HTTPS responses from the
 * target server and rewrites JSON payloads to show active subscription.
 *
 * HOW NSURLProtocol WORKS:
 *   When registered, iOS routes ALL matching URL requests through our
 *   protocol class FIRST. We can modify the request, intercept the response,
 *   or completely fabricate a new response before the app sees it.
 *
 * IMPORTANT: This only works for requests made through NSURLSession /
 * NSURLConnection (standard Foundation networking). If the app uses a
 * custom TCP/UDP socket library, this won't intercept those.
 *
 * REGISTRATION: Must be called VERY EARLY — before any networking code runs.
 *               We register it in the constructor (__attribute__((constructor))).
 */
@interface PTNetworkInterceptor : NSURLProtocol
@property (nonatomic, strong) NSMutableData *receivedData;
@property (nonatomic, strong) NSHTTPURLResponse *httpResponse;
@property (nonatomic, strong) NSURLSessionDataTask *dataTask;
@end

@implementation PTNetworkInterceptor

/**
 * Determines whether this protocol can handle a given request.
 * We return YES for ALL requests to our target hosts.
 */
+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *host = request.URL.host.lowercaseString;

    // Check if the host matches any of our targets
    for (NSString *targetHost in PT_GetTargetHosts()) {
        if ([host containsString:targetHost.lowercaseString] ||
            [host hasSuffix:targetHost.lowercaseString]) {
            return YES;
        }
    }

    // Also intercept any request with relevant path patterns
    NSString *path = request.URL.path.lowercaseString;
    for (NSString *pattern in PT_GetTargetPathPatterns()) {
        if ([path containsString:pattern.lowercaseString]) {
            return YES;
        }
    }

    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}

/**
 * Starts loading the intercepted request.
 * We make the real network request ourselves, then inspect and modify
 * the response before delivering it to the app.
 */
- (void)startLoading {
    self.receivedData = [NSMutableData data];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration
        defaultSessionConfiguration];
    config.protocolClasses = @[]; // Prevent infinite recursion

    // Copy headers from the original request
    config.HTTPAdditionalHeaders = self.request.allHTTPHeaderFields;

    NSURLSession *session = [NSURLSession sessionWithConfiguration:config
                                                          delegate:self
                                                     delegateQueue:nil];
    self.dataTask = [session dataTaskWithRequest:self.request];
    [self.dataTask resume];
}

- (void)stopLoading {
    [self.dataTask cancel];
}

#pragma mark NSURLSessionDataDelegate

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler
{
    self.httpResponse = (NSHTTPURLResponse *)response;

    PT_NET(@"Intercepted: %@ %@ (%ld)",
           dataTask.originalRequest.HTTPMethod,
           dataTask.originalRequest.URL.absoluteString,
           (long)response.statusCode);

    completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)dataTask
    didReceiveData:(NSData *)data
{
    [self.receivedData appendData:data];
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error
{
    if (error) {
        PT_ERR(@"Network error: %@", error.localizedDescription);
        [self.client URLProtocol:self didFailWithError:error];
        return;
    }

    NSData *responseData = [self.receivedData copy];

    // ==============================================================
    // CHECK CONTENT TYPE — Only modify JSON responses
    // ==============================================================
    NSString *contentType = self.httpResponse.allHeaderFields[@"Content-Type"] ?: @"";
    BOOL isJSON = [contentType containsString:@"json"] ||
                  [contentType containsString:@"text/plain"];

    if (isJSON && responseData.length > 0) {
        PT_NET(@"JSON response detected (%lu bytes) — attempting rewrite",
               (unsigned long)responseData.length);

        NSData *modifiedData = [self rewriteJSONResponse:responseData];

        if (modifiedData) {
            PT_NET(@"JSON rewritten successfully (%lu → %lu bytes)",
                   (unsigned long)responseData.length,
                   (unsigned long)modifiedData.length);
            responseData = modifiedData;
        } else {
            PT_NET(@"JSON rewrite skipped (no matching keys)");
        }
    }

    // ==============================================================
    // DELIVER RESPONSE TO THE APP
    // ==============================================================
    [self.client URLProtocol:self
          didReceiveResponse:self.httpResponse
          cacheStoragePolicy:NSURLCacheStorageNotAllowed];

    [self.client URLProtocol:self didLoadData:responseData];
    [self.client URLProtocolDidFinishLoading:self];
}

/**
 * Rewrites JSON response data to set subscription flags to true.
 *
 * This method:
 *   1. Parses the JSON
 *   2. Recursively searches for known subscription key patterns
 *   3. Sets matching boolean values to TRUE
 *   4. Sets matching string "status" values to "active"/"subscribed"
 *   5. Returns the modified JSON data
 */
- (NSData *)rewriteJSONResponse:(NSData *)originalData
{
    NSError *error = nil;
    id jsonObject = [NSJSONSerialization JSONObjectWithData:originalData
                                                  options:NSJSONReadingMutableContainers
                                                    error:&error];

    if (error || !jsonObject) {
        PT_NET(@"JSON parse failed: %@", error.localizedDescription);
        return nil;
    }

    int modifications = [self recursivelyRewrite:jsonObject];

    if (modifications == 0) {
        return nil; // Nothing changed
    }

    PT_NET(@"Made %d subscription flag modifications", modifications);

    return [NSJSONSerialization dataWithJSONObject:jsonObject
                                           options:0
                                             error:nil];
}

/**
 * Recursively walks through JSON structure (NSDictionary/NSArray)
 * and rewrites subscription-related keys to true/active values.
 *
 * @return Number of modifications made.
 */
- (int)recursivelyRewrite:(id)obj
{
    int count = 0;

    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *dict = (NSMutableDictionary *)obj;

        for (NSString *key in dict.allKeys) {
            NSString *lowerKey = key.lowercaseString;

            // ── Boolean flags ──
            if ([dict[key] isKindOfClass:[NSNumber class]]) {
                BOOL isBool = [dict[key] isKindOfClass:[NSNumber class]] &&
                              (strcmp([dict[key] objCType], "c") == 0 ||
                               strcmp([dict[key] objCType], "B") == 0 ||
                               [dict[key] isKindOfClass:@YES.class]);

                if (isBool) {
                    BOOL val = [dict[key] boolValue];

                    // Check if this key looks like a subscription flag
                    for (NSString *pattern in @[@"subscri", @"premium",
                                                 @"vip", @"isfree",
                                                 @"is_free", @"active",
                                                 @"canbuy", @"can_buy",
                                                 @"purchased", @"paid"]) {
                        if ([lowerKey containsString:pattern]) {
                            if (!val) {
                                dict[key] = @YES;
                                PT_NET(@"  [DICT] %@: %@ → YES", key, dict[key]);
                                count++;
                            }
                            break;
                        }
                    }
                }
            }

            // ── String values ──
            if ([dict[key] isKindOfClass:[NSString class]]) {
                NSString *val = (NSString *)dict[key];

                for (NSString *pattern in @[@"subscription_status",
                                             @"status", @"plan",
                                             @"plan_type", @"user_type",
                                             @"role", @"tier"]) {
                    if ([lowerKey containsString:pattern]) {
                        NSString *lowerVal = val.lowercaseString;
                        if ([lowerVal containsString:@"free"] ||
                            [lowerVal containsString:@"none"] ||
                            [lowerVal containsString:@"inactive"] ||
                            [lowerVal containsString:@"expired"] ||
                            [lowerVal isEqualToString:@"0"] ||
                            [lowerVal isEqualToString:@"false"]) {
                            dict[key] = @"active";
                            PT_NET(@"  [DICT] %@: '%@' → 'active'", key, val);
                            count++;
                        }
                        break;
                    }
                }
            }

            // ── Recurse into nested dicts ──
            if ([dict[key] isKindOfClass:[NSDictionary class]] ||
                [dict[key] isKindOfClass:[NSArray class]]) {
                count += [self recursivelyRewrite:dict[key]];
            }
        }
    }
    else if ([obj isKindOfClass:[NSArray class]]) {
        NSMutableArray *arr = (NSMutableArray *)obj;
        for (NSInteger i = 0; i < arr.count; i++) {
            if ([arr[i] isKindOfClass:[NSDictionary class]] ||
                [arr[i] isKindOfClass:[NSArray class]]) {
                count += [self recursivelyRewrite:arr[i]];
            }
        }
    }

    return count;
}

@end


#pragma mark - ══════════════════════════════════════════════════════════════
#pragma mark   ATTACK 2: UserDefaults Tampering (Swizzle object(forKey:))
#pragma mark - ══════════════════════════════════════════════════════════════

static IMP g_orig_NSUserDefaults_objectForKey = NULL;
static IMP g_orig_NSUserDefaults_setObject = NULL;

/**
 * Hooked NSUserDefaults.object(forKey:)
 *
 * Intercepts reads from UserDefaults. When the app reads a key that
 * matches subscription-related patterns, we return a "premium" value
 * instead of the real stored value.
 *
 * This catches cases where the app caches subscription data locally.
 */
static id PT_hook_objectForKey(id self, SEL _cmd, NSString *key)
{
    // Call original first
    id originalValue = ((id(*)(id, SEL, NSString *))g_orig_NSUserDefaults_objectForKey)(self, _cmd, key);

    if (!key) return originalValue;

    NSString *lowerKey = key.lowercaseString;

    // Check if this is a subscription-related key
    for (NSString *pattern in PT_GetTargetUserDefaultsKeys()) {
        if ([lowerKey containsString:pattern.lowercaseString]) {
            PT_UDS(@"objectForKey:'%@' → tampering", key);

            // Return appropriate fake value based on expected type
            if (originalValue == nil) {
                return @YES; // Default: pretend it's an active subscription
            }

            if ([originalValue isKindOfClass:[NSNumber class]]) {
                NSNumber *num = (NSNumber *)originalValue;
                // Check if it's a boolean
                if (strcmp(num.objCType, "c") == 0 ||
                    strcmp(num.objCType, "B") == 0) {
                    if (![num boolValue]) {
                        PT_UDS(@"  '%@': %@ → YES", key, originalValue);
                        return @YES;
                    }
                }
                // Check if it's an integer that means "free" or "inactive"
                if (strcmp(num.objCType, "i") == 0 ||
                    strcmp(num.objCType, "q") == 0) {
                    if ([num integerValue] == 0) {
                        PT_UDS(@"  '%@': %@ → 1", key, originalValue);
                        return @1;
                    }
                }
            }

            if ([originalValue isKindOfClass:[NSString class]]) {
                NSString *str = (NSString *)originalValue;
                NSString *lower = str.lowercaseString;
                if ([lower containsString:@"free"] ||
                    [lower containsString:@"none"] ||
                    [lower containsString:@"inactive"] ||
                    [lower containsString:@"expired"]) {
                    PT_UDS(@"  '%@': '%@' → 'premium'", key, str);
                    return @"premium";
                }
            }

            break;
        }
    }

    return originalValue;
}

/**
 * Hooked NSUserDefaults.setObject(forKey:)
 *
 * Intercepts writes to UserDefaults. When the app tries to store
 * subscription-related data (e.g., "subscription = inactive"), we
 * silently block the write to keep our tampered value intact.
 */
static void PT_hook_setObject(id self, SEL _cmd, id value, NSString *key)
{
    if (key) {
        NSString *lowerKey = key.lowercaseString;

        for (NSString *pattern in PT_GetTargetUserDefaultsKeys()) {
            if ([lowerKey containsString:pattern.lowercaseString]) {
                PT_UDS(@"setObject:'%@'='%@' → BLOCKED (keeping tampered value)",
                       key, value);

                // Silently eat the write — don't store the real value
                // This prevents the app from overwriting our fake data
                return;
            }
        }
    }

    // Pass through non-subscription writes normally
    ((void(*)(id, SEL, id, NSString *))g_orig_NSUserDefaults_setObject)(self, _cmd, value, key);
}


#pragma mark - ══════════════════════════════════════════════════════════════
#pragma mark   ATTACK 3: Enhanced Runtime Diagnostic
#pragma mark - ══════════════════════════════════════════════════════════════

/**
 * Dumps ALL classes in the ObjC runtime and searches for patterns.
 * This helps identify:
 *   - Any ObjC classes the app uses (even if not our direct targets)
 *   - Network-related classes (URLSession delegates)
 *   - Model classes that might be ObjC-accessible
 *   - Any class with subscription-related methods
 */
static void PT_RunEnhancedDiagnostic(void)
{
    unsigned int classCount = 0;
    Class *allClasses = objc_copyClassList(&classCount);

    PT_DIAG("=== ENHANCED RUNTIME DIAGNOSTIC ===");
    PT_DIAG("Total classes in runtime: %u", classCount);

    /* ── Search for target class names ── */
    PT_DIAG("--- Searching for target class names ---");
    int sectionHits = 0, studentHits = 0, modelHits = 0;
    int subscriptionHits = 0, purchaseHits = 0, storeHits = 0;

    for (unsigned int i = 0; i < classCount; i++) {
        const char *name = class_getName(allClasses[i]);

        if (strstr(name, "SectionModel")) { PT_DIAG("  [SECTION] %s", name); sectionHits++; }
        if (strstr(name, "StudentModel")) { PT_DIAG("  [STUDENT] %s", name); studentHits++; }
        if (strstr(name, "Section"))      { PT_DIAG("  [SECTION*] %s", name); sectionHits++; }
        if (strstr(name, "Student"))      { PT_DIAG("  [STUDENT*] %s", name); studentHits++; }
        if (strstr(name, "Model"))        { modelHits++; }
        if (strstr(name, "Subscri"))      { PT_DIAG("  [SUBSCRIB] %s", name); subscriptionHits++; }
        if (strstr(name, "Purchase"))     { PT_DIAG("  [PURCHASE] %s", name); purchaseHits++; }
        if (strstr(name, "Store") ||
            strstr(name, "IAP") ||
            strstr(name, "Payment"))      { PT_DIAG("  [STORE] %s", name); storeHits++; }
    }

    PT_DIAG("Results: Section=%d Student=%d Model=%d Subscription=%d Purchase=%d Store=%d",
           sectionHits, studentHits, modelHits, subscriptionHits, purchaseHits, storeHits);

    /* ── Search ALL methods for subscription-related selectors ── */
    PT_DIAG("--- Searching for subscription-related methods ---");
    int methodHits = 0;
    for (unsigned int i = 0; i < classCount; i++) {
        unsigned int mCount = 0;
        Method *methods = class_copyMethodList(allClasses[i], &mCount);

        for (unsigned int j = 0; j < mCount; j++) {
            const char *selName = sel_getName(method_getName(methods[j]));
            if (selName &&
                (strstr(selName, "subscri") ||
                 strstr(selName, "Subscri") ||
                 strstr(selName, "isFree") ||
                 strstr(selName, "is_free") ||
                 strstr(selName, "studentCan") ||
                 strstr(selName, "canBuy") ||
                 strstr(selName, "bySubscri") ||
                 strstr(selName, "purchase") ||
                 strstr(selName, "premium") ||
                 strstr(selName, "isVip") ||
                 strstr(selName, "isActive"))) {
                PT_DIAG("  [METHOD] -[%s %s]", class_getName(allClasses[i]), selName);
                methodHits++;
            }
        }
        if (methods) free(methods);
    }
    PT_DIAG("Total subscription-related methods found: %d", methodHits);

    /* ── Dump loaded dylibs (check for custom networking libs) ── */
    PT_DIAG("--- Loaded dylibs ---");
    uint32_t imgCount = _dyld_image_count();
    for (uint32_t i = 0; i < imgCount; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && (strstr(name, "xapps") || strstr(name, "Alamofire") ||
                     strstr(name, "AFNetworking") || strstr(name, "Moya") ||
                     strstr(name, "Socket") || strstr(name, "Starscream") ||
                     strstr(name, "GRPC") || strstr(name, "Apollo"))) {
            PT_DIAG("  [DYLIB] %s", name);
        }
    }

    /* ── Check NSUserDefaults contents ── */
    PT_DIAG("--- NSUserDefaults dump ---");
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *allDefaults = [defaults dictionaryRepresentation];
    for (NSString *key in allDefaults) {
        NSString *lowerKey = key.lowercaseString;
        for (NSString *pattern in PT_GetTargetUserDefaultsKeys()) {
            if ([lowerKey containsString:pattern.lowercaseString]) {
                PT_DIAG("  [UDS] %@ = %@", key, allDefaults[key]);
            }
        }
    }

    PT_DIAG("=== DIAGNOSTIC COMPLETE ===");

    if (allClasses) free(allClasses);
}


#pragma mark - ══════════════════════════════════════════════════════════════
#pragma mark   Utility: Pure Runtime Swizzle
#pragma mark - ══════════════════════════════════════════════════════════════

static BOOL PT_Swizzle(Class cls, SEL sel, IMP newIMP, IMP *origIMPPtr)
{
    if (!cls || !sel) return NO;
    Method method = class_getInstanceMethod(cls, sel);
    if (!method) return NO;
    IMP orig = method_getImplementation(method);
    if (origIMPPtr) *origIMPPtr = orig;
    method_setImplementation(method, newIMP);
    return YES;
}


#pragma mark - ══════════════════════════════════════════════════════════════
#pragma mark   Constructor — Entry Point
#pragma mark - ══════════════════════════════════════════════════════════════

__attribute__((constructor))
static void PentestTweak_v3_entry(void)
{
    @autoreleasepool {

        NSLog(@"[PT v3] ═════════════════════════════════════════════");
        NSLog(@"[PT v3]  PentestTweak v3.0 — Triple Attack");
        NSLog(@"[PT v3]  Pure Swift detected — bypassing model layer");
        NSLog(@"[PT v3] ═════════════════════════════════════════════");

        int ok = 0, err = 0;

        /* ══════════════════════════════════════════════════════════
         *  ATTACK 1: Register NSURLProtocol for network interception
         * ══════════════════════════════════════════════════════════ */
        PT_LOG("ATTACK 1: Registering network interceptor...");

        [NSURLProtocol registerClass:[PTNetworkInterceptor class]];

        // Also hook the NSURLSession delegate to catch any requests
        // that might bypass our NSURLProtocol
        PT_LOG("  NSURLProtocol registered: %@", [PTNetworkInterceptor class]);
        ok++;

        /* ══════════════════════════════════════════════════════════
         *  ATTACK 2: Swizzle NSUserDefaults for local storage tampering
         * ══════════════════════════════════════════════════════════ */
        PT_LOG("ATTACK 2: Swizzling NSUserDefaults...");

        Class udClass = objc_getClass("NSUserDefaults");
        if (udClass) {
            if (PT_Swizzle(udClass,
                          sel_registerName("objectForKey:"),
                          (IMP)PT_hook_objectForKey,
                          &g_orig_NSUserDefaults_objectForKey)) {
                PT_LOG("  Hooked -[NSUserDefaults objectForKey:]");
                ok++;
            } else {
                PT_ERR("  Failed to hook objectForKey:");
                err++;
            }

            if (PT_Swizzle(udClass,
                          sel_registerName("setObject:forKey:"),
                          (IMP)PT_hook_setObject,
                          &g_orig_NSUserDefaults_setObject)) {
                PT_LOG("  Hooked -[NSUserDefaults setObject:forKey:]");
                ok++;
            } else {
                PT_ERR("  Failed to hook setObject:forKey:");
                err++;
            }

            // Also try to tamper with EXISTING stored values right now
            PT_LOG("  Tampering existing UserDefaults values...");
            NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
            for (NSString *key in PT_GetTargetUserDefaultsKeys()) {
                // Search for keys containing this pattern
                for (NSString *storedKey in [[defaults dictionaryRepresentation] allKeys]) {
                    if ([storedKey.lowercaseString containsString:key.lowercaseString]) {
                        id val = [defaults objectForKey:storedKey];
                        PT_UDS(@"  Found existing: %@ = %@", storedKey, val);
                        // Don't overwrite here — the hook will handle reads
                    }
                }
            }
        } else {
            PT_ERR("  NSUserDefaults class not found!");
            err++;
        }

        /* ══════════════════════════════════════════════════════════
         *  ATTACK 3: Run enhanced diagnostic
         * ══════════════════════════════════════════════════════════ */
        PT_LOG("ATTACK 3: Running enhanced runtime diagnostic...");
        PT_RunEnhancedDiagnostic();
        ok++;

        /* ══════════════════════════════════════════════════════════
         *  SUMMARY
         * ══════════════════════════════════════════════════════════ */
        NSLog(@"[PT v3] ═════════════════════════════════════════════");
        NSLog(@"[PT v3]  RESULT: %d / %d attacks deployed", ok, ok + err);
        NSLog(@"[PT v3]  STATUS:");
        NSLog(@"[PT v3]    [NET]  HTTP interception: ACTIVE");
        NSLog(@"[PT v3]    [UDS]  UserDefaults tampering: %@", (g_orig_NSUserDefaults_objectForKey ? @"ACTIVE" : @"FAILED"));
        NSLog(@"[PT v3]    [DIAG] Runtime diagnostic: COMPLETE");
        NSLog(@"[PT v3] ");
        NSLog(@"[PT v3]  NEXT: Check [PT v3][NET] logs for intercepted API calls.");
        NSLog(@"[PT v3]  If no [NET] logs appear, the app may use custom");
        NSLog(@"[PT v3]  networking or WKWebView. Share diagnostic output.");
        NSLog(@"[PT v3] ═════════════════════════════════════════════");

    } /* @autoreleasepool */
}
