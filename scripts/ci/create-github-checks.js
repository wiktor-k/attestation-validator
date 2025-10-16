const execSync = require("child_process").execSync;
const fs = require("fs");

const getMetadata = (attributes, key) => attributes
    .filter(attribute => 'metadata' in attribute)
    .flatMap(attribute => {
        let meta = attribute.metadata;
        let metaKey = meta[0];
        if (metaKey === key) {
            return meta.slice(1);
        } else {
            return [];
        }
    });

const getRecipePackages = (recipes, name) => {
    const recipe = recipes[name];
    const direct = getMetadata(recipe.attributes, 'pacman');
    const indirectDeps = recipe.body
        .filter(item => String(item[0]).startsWith('just '))
        .flatMap(item => item[0].split(' '))
        .filter(item => item !== 'just' && !item.startsWith('--'));
    direct.push(...indirectDeps.flatMap(dep => getRecipePackages(recipes, dep)));
    return direct;
}

const recipes = [];

for (const file of fs
    .readdirSync(".")
    .filter((file) => file === ".justfile" || file.endsWith(".just"))) {
    const justfile = JSON.parse(
        execSync(`just --justfile ${file} --dump --dump-format=json`, {
            encoding: "utf-8",
        }),
    );

    recipes.push(
        ...Object.values(justfile.recipes)
            .filter((recipe) =>
                recipe.attributes.some((attribute) => attribute.group == "ci"),
            )
            .map((recipe) => {
                return {
                    file,
                    packages:  getRecipePackages(justfile.recipes, recipe.name).join(' '),
                    conditional: getMetadata(recipe.attributes, 'github-if'),
                    name: recipe.name,
                    doc: recipe.doc
                };
            }),
    );
}

fs.appendFileSync(
    process.env.GITHUB_OUTPUT,
    `recipes=` + JSON.stringify({ recipes }),
);