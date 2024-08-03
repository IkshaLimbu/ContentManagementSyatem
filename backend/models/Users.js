const { DataTypes } = require('sequelize');
const sequelize = require('../config/db')

const Users = sequelize.define('Users', {
    name: {
        type: DataTypes.STRING,
    },
    email: {
        type: DataTypes.STRING,
    },
    password: {
        type: DataTypes.STRING,
    },
    type :{
        type: DataTypes.STRING,
        defaultValue: 'user'
    }

});

module.exports = Users;