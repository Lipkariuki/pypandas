const dotenv = require('dotenv');
const mongoose = require('mongoose');
dotenv.config({ path: './config.env' });

const app = require('./app');

const DB = process.env.DATABASE_LOCAL;

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false
  })
  .then(() => console.log('DB connected'));
mongoose.set('debug', true);

const port = process.env.PORT || 3000;

process.on('unhandledRejection', err => {
  console.log(err.name, err.message);
  process.exit(1);
});

app.listen(port, () =>
  console.log(
    `server is running on --> http://localhost:${port}/api/v1`
  )
);
