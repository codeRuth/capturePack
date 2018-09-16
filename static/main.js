var app = new Vue({
  el: '#app',
  data: {
    image: '',
    message: 'hellow'
  },
  methods: {
    onFileChange(e) {
      var files = e.target.files || e.dataTransfer.files;
      if (!files.length)
        return;
      let formData = new FormData();
      formData.append('file', files[0]);

      this.upload(formData);
    },
    upload (formData) {
      axios.post('/process', formData, { headers: { 'Content-Type': 'multipart/form-data' }})
      .then(function (response) {
        console.log(response.data)
      })
      .catch(function (error) {
        console.log(error);
      });
    },
    createImage(file) {
      var image = new Image();
      var reader = new FileReader();
      var vm = this;

      reader.onload = (e) => {
        vm.image = e.target.result;
      };
      reader.readAsDataURL(file);
    },
    removeImage: function (e) {
      this.image = '';
    }
  }
})