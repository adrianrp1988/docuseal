namespace :admin do
  resources :ldap_provisioning_conflicts, only: %i[index show] do
    member do
      post :approve_link
      post :approve_provision
      post :reject
    end
  end
end
