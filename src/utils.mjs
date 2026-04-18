
export function getPaginationParams(query) {
    const limit = isPositiveNumber(query.limit, 20);
    const offset = isPositiveNumber(query.offset, 0);
    const sort = isString(query.sort, 'created_at:desc');
    return { limit, offset, sort };
}

export function expressError(code, message, req, res){
    // return { code, message };
    console.log("--------------------------------");
    console.log("SERVER ERROR");
    console.log("--------------------------------");
    console.log('Request Details:');
    console.log({
        method: req.method,
        url: req.url,
        body: req.body,
        query: req.query,
        params: req.params,
        headers: req.headers,
        ip: req.ip,
        userAgent: req.userAgent,
        referer: req.referer,
        origin: req.origin,
        host: req.host,
        port: req.port,
        protocol: req.protocol,
        secure: req.secure,
        xhr: req.xhr,
        flash: req.flash,
        signedCookies: req.signedCookies,
        cookies: req.cookies,
        session: req.session,
    });
    console.log("--------------------------------");
    console.log('Error Details:');
    console.log({ code, message });
    console.log("--------------------------------");
    return res.status(code).json({ error: message });

}