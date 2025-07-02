import { test } from "vitest";

export function testCases<T>(testDescription: string, cases: T[], testFunction: (testCase: T) => Promise<void> | void) {
    test(testDescription, async () => {
        for (const [i, testCase] of cases.entries()) {
            try {
                await testFunction(testCase);
            } catch (error) {
                console.error(`Error occurred while testing case ${i}: ${JSON.stringify(testCase)}`, error);
                throw error; // Re-throw the error to fail the test
            }
        }
    });
};