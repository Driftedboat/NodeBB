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
	if (isGuest(req, res)) return;

	const path = req.path.replace(/^(\/api)?(\/v3)?\/admin\/?/g, '');
  
	// Check if access is denied
	const accessDenied = await isAccessDenied(path, req, res);
	if (accessDenied) return;
  
	// Check if has no password set
	const noPassword = await hasNoPassword(req);
	if (noPassword) return res.status(401); 
	// Handle re-login
	const reLoginHandled = await handleReLogin(req, res);
	if (reLoginHandled) return;
  
	//  call next if none of the above checks stopped execution
	next();
});

// helper fucntions
function isGuest(req, res) {
	if (req.uid <= 0) {
		controllers.helpers.notAllowed(req, res);
		return true;
	}
	return false;
}
function isAccessDenied(path, req, res, callback) {
	if (path) {
		const privilege = privileges.admin.resolve(path);
		privileges.admin.can(privilege, req.uid, async (err, canAccess) => {
			if (err || !canAccess) {
				controllers.helpers.notAllowed(req, res);
				callback(true);
			} else {
				callback(false);
			}
		});
	} else {
		privileges.admin.get(req.uid, async (err, privilegeSet) => {
			if (err || !Object.values(privilegeSet).some(Boolean)) {
				controllers.helpers.notAllowed(req, res);
				callback(true);
			} else {
				callback(false);
			}
		});
	}
}
function hasNoPassword(req, next, callback) {
	user.hasPassword(req.uid, (err, hasPassword) => {
		if (err || !hasPassword) {
			resolve(true);
		} else {
			resolve(false);
		}
	});
}
function handleReLogin(req, res, next, callback) {
	const loginTime = req.session.meta ? req.session.meta.datetime : 0;
	const adminReloginDuration = meta.config.adminReloginDuration * 60000;
	const disabled = meta.config.adminReloginDuration === 0;
	if (disabled || (loginTime && parseInt(loginTime, 10) > Date.now() - adminReloginDuration)) {
		extendLogoutTimer(req.session.meta, loginTime, adminReloginDuration);
		return true;
	} else {
		return false;
	}
}
function extendLogoutTimer(meta, loginTime, adminReloginDuration) {
	const timeLeft = parseInt(loginTime, 10) - (Date.now() - adminReloginDuration);
	if (meta && timeLeft < Math.min(60000, adminReloginDuration)) {
		meta.datetime += Math.min(60000, adminReloginDuration);
	}
}
