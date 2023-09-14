import axios from 'axios';

const LOGIN_API_BASE_URL = '/login';
const ROLE_API_URL = '/api/v1/users/role';
class LoginService{

    async getLogin(user){
        var fdata = new FormData();
        fdata.append('username', user.userName);
        fdata.append('password', user.password);
        return axios({
            method: "post",
            url: LOGIN_API_BASE_URL,
            data: fdata,
            headers: { "Content-Type": "multipart/form-data" },
          });
    }

    async getRoles(userName){
        
        return axios.get(`${ROLE_API_URL}/${userName}`);
    }
}

export default new LoginService();

