// prisma/seed.ts

import { PrismaClient } from "@prisma/client";
import { faker } from "@faker-js/faker";

const prisma = new PrismaClient({
	datasources: {
		db: {
			url: process.env.DATABASE_URL,
		},
	},
});

async function main() {
  console.log(`Start seeding ...`);

  for (const _ of Array(50).fill(null)) {
    const user = await prisma.user.create({
      data: {
        name: faker.person.firstName(),
        email: faker.internet.email(),
        avatar: faker.image.urlPicsumPhotos() || faker.image.avatar(),
        posts: {
          create: {
            title: faker.lorem.sentence(),
            content: faker.lorem.paragraph().slice(0, 20),
            published: faker.datatype.boolean(),
          },
        },
      }
    })
    console.log(`Created user with id: ${user.id}`)
  }
  console.log(`Seeding finished.`)
}

main()
  .then(async () => {
    await prisma.$disconnect()
  })
  .catch(async (e) => {
    console.error(e)
    await prisma.$disconnect()
    process.exit(1)
  })
