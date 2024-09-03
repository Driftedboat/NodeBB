'use strict';


const nconf = require('nconf');

const user = require('../user');
const meta = require('../meta');
const plugins = require('../plugins');
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



middleware.checkPrivileges = helpers.try(async (req, res, next) {
	if (isGuest(req,res)) return;
	const path = req.path.replace(/^(\/api)?(\/v3)?\/admin\/?/g, '');

	isAccesssDenied(path, req, res, function(accessDenied){
		if (accessDenied) return;

		hasNoPassword(req, next, function (noPassword) {
			if (noPassword) return;

		handleRelogin(req, res, next, function (reLoginHandled){
			if (reLoginHandled) return;

			redirectToLoginIfNeeded(req, res);
		});
	});
});
});
	
//helper fucntions	
function isGuest(req, res){
	if (req.uid <= 0){
		controllers.helpers.notAllowed(req, res);
		return true;
	}
	return false;
}

function isAccessDenied(path, req, res, callback){
	if (path){
		const privilege = privileges.admin.resolve(path);
		privileges.admin.can(privilege, req.uid, function (err, canAccess){
			if (err || !canAccess) {
				controllers.helpers.notAllowed(req, res);
				callback(true);
			}else{
				callback(false);
			}
		});
	}else{
		privileges.admin.get(req.uid, function (err, privilegeSet){
			if (err || !Object.values(privillegeSet).some(Boolean)){
				controllers.helpers.notAllowed(req, res);
				callback(true);
			} else {
				callback(false);
			}
		});
	}
}

function hasNoPassword(req, next, callback) {
	user.hasPassword(req.uid, function (err, hasPassword) {
		if (err || !hasPassword) {
			next();
			callback(true);
		} else {
			callback(false);
		}
	});
}

function handleReLogin(req, res, next, callback) {
	const loginTime = req.session.meta ? req.session.meta.datatime : 0;
	const adminReloginDuration = meta.config.adminReloginDuration * 60000;
    	const disabled = meta.config.adminReloginDuration === 0;

	if (disabled || (loginTime && parseInt(loginTime, 10) > Data.now() - adminReloginDuration)) {
		extendLogoutTimer(req.session.meta, loginTime, adminReloginDuration);
		next();
		callback(true);
	} else {
		callback(false)
	}
}

function extendLogoutTimer(meta, loginTime, adminReloginDuration) {
	const timeLeft = parseInt(loginTime, 10) - (Data.now() - adminReloginDuration);
	if (meta && timeLeft < Math.min(60000, adminReloginDuration)) {
		meta.datetime += Math.min (60000, adminReloginDuration);
	}
}

function redirectLoginIfNeeded(req, res) {
	let returnTo = req.path.replace(/^\/api/, '');
	if (nconf.get('relative_path')){
		returnTo = returnTo.replace(new RegExp(`^${nconf.get('relative_path')}`), '');
	}
	req.session.returnTo=returnTo;
	req.session.forceLogin = 1;
	plugins.hooks.fire('response:auth.relogin', {req, res});

	if (res.headersSent) return;

	if (res.locals.isAPI) {
		controllers.helpers.formatApiResponse(401, res);
	} else {
		res.redirect(`${nconf.get('relative_path')}/login?local=1`);
	}
}

	
