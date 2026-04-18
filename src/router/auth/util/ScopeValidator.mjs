/**
 * ScopeValidator - Utility for validating scope inheritance and taxonomy.
 */
export class ScopeValidator {
    /**
     * Checks if candidateScopes is a subset of authorizedScopes.
     * Supports wildcard '*' in authorizedScopes.
     */
    static isSubset(candidateScopes, authorizedScopes) {
        if (!Array.isArray(candidateScopes) || !Array.isArray(authorizedScopes)) {
            return false;
        }

        if (authorizedScopes.includes('*')) {
            return true;
        }

        return candidateScopes.every(scope => authorizedScopes.includes(scope));
    }

    /**
     * Resolves wildcards and role definitions into a flat array of unique scopes.
     * @param {string[]} scopes - The scopes to expand.
     * @param {string[]} taxonomy - The full list of valid scopes.
     */
    static expand(scopes, taxonomy) {
        if (scopes.includes('*')) {
            return [...new Set(taxonomy)];
        }
        return [...new Set(scopes.filter(s => taxonomy.includes(s)))];
    }
    
    /**
     * Checks if all scopes are present in the taxonomy.
     */
    static isValidTaxonomy(scopes, taxonomy) {
        if (scopes.includes('*')) return true;
        return scopes.every(s => taxonomy.includes(s));
    }
}
