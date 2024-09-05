'use strict';


// const nconf = require('nconf');

const user = require('../user');
const meta = require('../meta');
// const plugins = require('../plugins');
const privileges = require('../privileges');
const helpers = require('./helpers');

const controllers = {
	admin: require('../controllers/admin'),
	helpers: require('../controllers/helpers'),
};

const middleware = module.exports;

middleware.buildHeader = helpers.try(async (req, res, next) => {
	res.locals.renderAdminHeader = true;
	if (req.method === 'GET') {
		await require('./index').applyCSRFasync(req, res);
	}

	res.locals.config = await controllers.admin.loadConfig(req);
	next();
});

middleware.checkPrivileges = helpers.try(async (req, res, next) => {
	// Check if the user is a guest
	if (isGuest(req)) return;
	const path = req.path.replace(/^(\/api)?(\/v3)?\/admin\/?/g, '');

	isAccessDenied(path, req, res, (accessDenied) => {
		if (accessDenied) return;
		// Check if the user has no password set
		hasNoPassword(req, (noPassword) => {
			if (noPassword) return;
			// Handle re-login
			handleReLogin(req, res, (reLoginHandled) => {
				if (reLoginHandled) return;
				next();
			});
		});
	});
});

// helper fucntions
function isGuest(req) {
	if (req.uid <= 0) {
		return true;
	}
	return false;
}
function isAccessDenied(path, req, res, callback) {
	if (path) {
		const privilege = privileges.admin.resolve(path);
		privileges.admin.can(privilege, req.uid, (err, canAccess) => {
			if (err || !canAccess) {
				controllers.helpers.notAllowed(req, res);
				callback(true);
			} else {
				callback(false);
			}
		});
	} else {
		privileges.admin.get(req.uid, (err, privilegeSet) => {
			if (err || !Object.values(privilegeSet).some(Boolean)) {
				controllers.helpers.notAllowed(req, res);
				callback(true);
			} else {
				callback(false);
			}
		});
	}
}
function hasNoPassword(req, callback) {
	user.hasPassword(req.uid, (err, hasPassword) => {
		if (err || !hasPassword) {
			callback(true);
		} else {
			callback(false);
		}
	});
}
function handleReLogin(req, res, callback) {
	const loginTime = req.session.meta ? req.session.meta.datetime : 0;
	const adminReloginDuration = meta.config.adminReloginDuration * 60000;
	const disabled = meta.config.adminReloginDuration === 0;

	if (disabled || (loginTime && parseInt(loginTime, 10) > Date.now() - adminReloginDuration)) {
		extendLogoutTimer(req.session.meta, loginTime, adminReloginDuration);
		res.redirect('/login'); // Handle re-login with redirection
		callback(true);
	} else {
		callback(false);
	}
}
function extendLogoutTimer(meta, loginTime, adminReloginDuration) {
	const timeLeft = parseInt(loginTime, 10) - (Date.now() - adminReloginDuration);
	if (meta && timeLeft < Math.min(60000, adminReloginDuration)) {
		meta.datetime += Math.min(60000, adminReloginDuration);
	}
}
