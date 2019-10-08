const addjectifier = adjective => {
  console.log('hello');
  return data => {
    console.log('world');
    return `${adjective} ${data} `;
  };
};

let coolifier = addjectifier('cool');

console.log(coolifier('dude'));
