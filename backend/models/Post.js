const {DataTypes}= require('sequelize');
const sequelize = require('../config/db');
const Users = require('./Users');
const { FOREIGNKEYS } = require('sequelize/lib/query-types');

const Post = sequelize.define('Post', {
    description: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    userId: {
        type: DataTypes.INTEGER,
        references: {
            model: Users,
            key: 'id',
        }
    }

})
Post.belongsTo(Users, {foreignKey: 'userId'});
Users.hasMany(Post, {foreignKey: 'userId'});//set one to many relationship


module.exports = Post;