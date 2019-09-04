let path = require("path");
let glob = require("glob");

let webpackConfig = require("./webpack.config.js");

// Clear existing .scss rule(s) out of webpack config, we need special handling
// here.
webpackConfig.module.rules = webpackConfig.module.rules.filter(value => {
    return value.test.toString() != /\.scss$/.toString();
});

webpackConfig.module.rules.push({
    test: /\.scss$/,
    use: [
        {
            loader: "style-loader"
        },
        {
            loader: "css-loader",
            options: {
                alias: {
                    "../images": path.resolve(__dirname, "../static/images"),
                    ".": path.resolve(__dirname, "../static/style/blue")
                }
            }
        },
        {
            loader: "sass-loader",
            options: {
                sourceMap: true
            }
        }
    ]
});

webpackConfig.module.rules.push({ test: /\.(png|jpg|gif|eot|ttf|woff|woff2|svg)$/, use: ["file-loader"] });

sections = [];

glob("./galaxy/docs/galaxy-*.md", (err, files) => {
    files.forEach(file => {
        name = file.match(/galaxy-(\w+).md/)[1];
        sections.push({ name: "Galaxy " + name, content: file });
    });
}),
    sections.push(
        ...[
            {
                name: "Basic Bootstrap Styles",
                content: "./galaxy/docs/bootstrap.md"
            }
            // This will require additional configuration
            // {
            //     name: 'Components',
            //     components: './galaxy/scripts/components/*.vue'
            // }
        ]
    );

module.exports = {
    webpackConfig,
    sections,
    require: ["./galaxy/style/scss/base.scss"]
};
