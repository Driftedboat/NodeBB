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


			

	
