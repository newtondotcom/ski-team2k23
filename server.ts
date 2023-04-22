import { error } from '@sveltejs/kit';
import { auth } from '$lib/server/lucia';
import { parseStringPromise as xml2ks } from 'xml2js';
import { prisma } from '$lib/server/prisma';
import { PUBLIC_CAS_URL } from '$env/static/public';
import type { RequestHandler } from './$types';

// Get the ticket from the query string.
const getTicket = (url: URL) => {
	const params = new URLSearchParams(url.search);
	return params.get('ticket');
};

export const GET: RequestHandler = async ({ url, locals }) => {
	const ticket = getTicket(url);
	if (!ticket) throw error(400, 'No ticket provided.');
	// Retrieve the user data from the CAS server.
	try {
		const data = await fetch(
			`${PUBLIC_CAS_URL}/serviceValidate?ticket=${ticket}&service=${url.origin}/loginCAS`
		);
		const xml = await data.text();
		// Parse the XML response into a JavaScript object.
		const json = await xml2ks(xml, { explicitArray: false });
		// Extract the user groups from the response.
		const groups =
			json['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes']['cas:groups'];
		// Check if the user is a member of the "animation-n7" group.
		if (!groups.includes('animation-n7'))
			throw error(403, 'You are not allowed to access this page.');
		// Get the user data from the response.
		const userData = {
			username: json['cas:serviceResponse']['cas:authenticationSuccess']['cas:user'],
			email:
				json['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes']['cas:email'],
			first_name:
				json['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes'][
					'cas:first_name'
				],
			last_name:
				json['cas:serviceResponse']['cas:authenticationSuccess']['cas:attributes']['cas:last_name']
		};
		// If the user does not exist, create it.
		const user = await prisma.user.findUnique({
			where: {
				username: userData.username
			}
		});
		if (user == null) {
			// Create the user.
			await auth.createUser({
				primaryKey: {
					providerId: 'cas',
					providerUserId: userData.username,
					password: null
				},
				attributes: {
					username: userData.username,
					email: userData.email,
					firstName: userData.first_name,
					lastName: userData.last_name
				}
			});
		}
		// Get the key for the user.
		const key = await auth.useKey('cas', userData.username, null);
		// Create a session for the user.
		const session = await auth.createSession(key.userId);
		// Redirect the user to the login page.
		locals.setSession(session);
		// Redirect the user to the home page.
		return new Response('Redirect', {
			status: 303,
			headers: { Location: '/' }
		});
	} catch {
		throw error(500, 'An error occurred while retrieving the user data from the CAS server.');
	}
};
