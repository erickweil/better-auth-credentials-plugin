
import { MongoClient } from "mongodb";
import type { TestProject } from "vitest/node";

export default async function setup(project: TestProject) {

    const client = new MongoClient(project.config.env.DB_URL_AUTH!);
    const db = client.db();

    await db.dropDatabase();

    // Close the connection to the database
    await client.close();
    
}

