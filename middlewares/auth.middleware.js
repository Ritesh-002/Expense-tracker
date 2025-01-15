import jwt from 'jsonwebtoken'

function isLoggedIn(req, res, next) {
    const { token } = req.cookies
    if (!token) return res.status(401).json({ error: 'Access denied' });
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({
            error: 'Invalid token'
        });
    }
};

export default isLoggedIn;
