<template>
    <div class="container">
        <h1 class="text-center">Update Account</h1>
        <form @submit.prevent="updateAccount">
            <!-- Form fields here -->
            
            <div class="form-group">
                <label for="account_id">Account ID</label>
                <input type="text" id="id" v-model="account.id" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="name">Name</label>
                <input type="text" id="name" v-model="account.name" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="amount">Password</label>
                <input type="text" id="password" v-model="account.password" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="email">Email</label>
                <input type="text" id="email" v-model="account.email" class="form-control" required>
            </div>
            <div class="form-group">
                <label for="address">Address</label>
                <input type="text" id="address" v-model="account.address" class="form-control" required>
            </div>
            <!-- Other form fields -->
            <button type="submit" class="btn btn-primary">Submit</button>
        </form>
    </div>
</template>

<script>
import AccountService from '@/services/AccountService';

export default {
    name: 'UpdateAccount',
    data() {
        return {
            account: {
                id: '',
                name: '',
                password: '',
                email: '',
                address: ''
            }
        };
    },
    created() {
        this.updateAccount();
        // this.editAccounts();
    },
    methods: {
        updateAccount() {
            // Call your backend service to make the transaction
            AccountService.updateAccount(this.account)
                .then((response) => {
                    // Handle the response, e.g., show a success message
                    console.log('Account Updated:', response.data);
                    // Clear the form
                    this.account = {
                        id: '',
                        name: '',
                        password: '',
                        email: '',
                        address: ''
                    };
                })
                .catch((error) => {
                    // Handle errors, e.g., show an error message
                    console.error('Account failed:', error);
                });
        }
    }
};
</script>
