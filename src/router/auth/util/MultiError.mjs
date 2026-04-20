export default class MultiError extends Error {
    constructor(errors = []) {
        super();
        this.errors = Array.isArray(errors) ? errors : [];
    }

    add(error) {
        this.errors.push(error);
    }

    get count() {
        return this.errors.length;
    }

    build() {
        const messages = this.errors.map(err => 
            typeof err === 'string' ? err : err.message || 'Unknown error'
        );
        return new Error(`${this.count} errors occurred: ${messages.join(', ')}`);
    }

    throw() {
        throw this;
    }

    get message() {
        return this.build().message;
    }
}
