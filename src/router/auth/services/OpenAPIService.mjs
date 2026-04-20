/**
 * OpenAPIService - Generates and manages the OpenAPI specification for the Scope API.
 */
export class OpenAPIService {
    #spec;

    constructor(baseUrl = '/auth') {
        this.#spec = {
            openapi: '3.0.0',
            info: {
                title: 'Express Easy Auth',
                version: '1.0.0',
                description: 'Powerful, SOLID-compliant authentication library for Express.js'
            },
            servers: [
                { url: baseUrl }
            ],
            paths: {
                '/register': {
                    post: {
                        summary: 'Register a new user',
                        responses: {
                            200: { description: 'User registered successfully' }
                        }
                    }
                },
                '/login': {
                    post: {
                        summary: 'Log in a user',
                        responses: {
                            200: { description: 'Login successful' }
                        }
                    }
                },
                '/me': {
                    get: {
                        summary: 'Get current user info',
                        security: [{ bearerAuth: [] }],
                        responses: {
                            200: { description: 'User details' }
                        }
                    }
                }
            },
            components: {
                securitySchemes: {
                    bearerAuth: {
                        type: 'http',
                        scheme: 'bearer',
                        description: 'API key with sk_ prefix, e.g. "Bearer sk_..."',
                    },
                    apiKeyAuth: {
                        type: 'apiKey',
                        in: 'header',
                        name: 'x-api-key'
                    }
                }
            }
        };
    }

    getSpec() {
        return this.#spec;
    }
}
