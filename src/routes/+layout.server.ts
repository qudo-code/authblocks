import prisma from "$lib/server/prisma";

export const load = async () => {
	const users = await prisma.user.findMany();

    return {
        users
    }
}
	