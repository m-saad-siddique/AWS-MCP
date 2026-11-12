#import <Foundation/Foundation.h>
#import <Security/Security.h>

// Credentials are exchanged over pipes only. Never accept secrets in argv or log them.
static void respond(NSDictionary *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    if (data) [[NSFileHandle fileHandleWithStandardOutput] writeData:data];
}
int main(void) {
    @autoreleasepool {
        NSData *input = [[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
        id raw = input.length <= 2 * 1024 * 1024 ? [NSJSONSerialization JSONObjectWithData:input options:0 error:nil] : nil;
        if (![raw isKindOfClass:[NSDictionary class]]) { respond(@{@"ok":@NO,@"error":@"Invalid Keychain request."}); return 1; }
        NSDictionary *request = raw;
        NSString *operation = request[@"operation"], *service = request[@"service"], *account = request[@"account"];
        NSCharacterSet *notHex = [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet];
        if (![operation isKindOfClass:[NSString class]] || ![service isKindOfClass:[NSString class]] ||
            !([service isEqualToString:@"com.aws-approval-mcp.mfa-sessions"] || [service isEqualToString:@"com.aws-approval-mcp.mfa-sessions.test"]) ||
            ![account isKindOfClass:[NSString class]] || account.length != 64 || [account rangeOfCharacterFromSet:notHex].location != NSNotFound) {
            respond(@{@"ok":@NO,@"error":@"Invalid Keychain request."}); return 1;
        }
        SecKeychainSetUserInteractionAllowed([request[@"interactive"] boolValue]);
        NSDictionary *query = @{(__bridge id)kSecClass:(__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService:service, (__bridge id)kSecAttrAccount:account,
            (__bridge id)kSecAttrSynchronizable:@NO};
        OSStatus status = errSecParam;
        if ([operation isEqualToString:@"get"]) {
            NSMutableDictionary *search = [query mutableCopy];
            search[(__bridge id)kSecReturnData] = @YES;
            search[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitOne;
            CFTypeRef found = NULL;
            status = SecItemCopyMatching((__bridge CFDictionaryRef)search, &found);
            if (status == errSecItemNotFound) { respond(@{@"ok":@YES,@"value":[NSNull null]}); return 0; }
            if (status == errSecSuccess && found) {
                NSData *data = CFBridgingRelease(found);
                NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                if (value) { respond(@{@"ok":@YES,@"value":value}); return 0; }
            }
        } else if ([operation isEqualToString:@"set"]) {
            id value = request[@"value"];
            if (![value isKindOfClass:[NSString class]] || [value lengthOfBytesUsingEncoding:NSUTF8StringEncoding] > 1024 * 1024) {
                respond(@{@"ok":@NO,@"error":@"Invalid Keychain value."}); return 1;
            }
            NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
            status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)@{(__bridge id)kSecValueData:data});
            if (status == errSecItemNotFound) {
                NSMutableDictionary *add = [query mutableCopy];
                add[(__bridge id)kSecValueData] = data;
                add[(__bridge id)kSecAttrLabel] = @"AWS MCP · temporary MFA sessions";
                status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
            }
        } else if ([operation isEqualToString:@"delete"]) {
            status = SecItemDelete((__bridge CFDictionaryRef)query);
            if (status == errSecItemNotFound) status = errSecSuccess;
        }
        if (status == errSecSuccess) { respond(@{@"ok":@YES}); return 0; }
        respond(@{@"ok":@NO,@"error":@"Keychain access failed.",@"status":@(status)}); return 1;
    }
}
