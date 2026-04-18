export function isNumber(value, defaultValue = 0) {
    return typeof value === 'number' ? value : defaultValue;
}

export function isPositiveNumber(value, defaultValue = 0) {
    return isNumber(value, defaultValue) > 0 ? value : defaultValue;
}

export function isString(value, defaultValue = '') {
    return typeof value === 'string' ? value : defaultValue;
}