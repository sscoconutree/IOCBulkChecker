function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function isIPv4Address(input) {
    const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/; 
    return ipv4Regex.test(input);
}

function isIPv6Address(input) {
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^([0-9a-fA-F]{1,4}:){1,7}:|^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|^:((:[0-9a-fA-F]{1,4}){1,7}|:)|^fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|^::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|^([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$/;
    return ipv6Regex.test(input);
}

function isURL(input) {
    const URLregex = /^(?:https?:\/\/)?(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)$/;
    return URLregex.test(input);
}

function isHash(input) {
    
    const hashLength = input.length;

    if (hashLength === 32 || hashLength === 40 || hashLength === 64) {
        return true; 
    } else {
        return false; 
    }
}

module.exports = {
    sleep,
    isIPv4Address,
    isIPv6Address,
    isURL,
    isHash
};
