# ActsAsRole
module ActsAsRole

  # Determines if a user can access a route
  # True if:
  # - Route not protected (no permission)
  # - Route requires a role and user has role
  # Otherwise, false.
  #
  def has_access?(*args)
    # Find the set of roles required to access
    # the controller/action
    required_roles = roles_for_path(*args)

    if required_roles == false # feature unprotected
      return true
    elsif required_roles.empty? # feature disabled
      return false
    end
    
    # The acts_as_authenticated plugin will set the current_user
    # to false if authentication fails.
    return false if current_user == :false

    # If the feature is protected the user must be logged in
    # and have one or more of the required roles.
    return current_user && !(current_user.roles & required_roles).empty?
  end
  
  # If a path IS NOT protected return False.
  #
  # If a path is protected returns a set of enabled roles
  # configured to permit access to this path.
  #
  def roles_for_path(*args)
    
    hash = args_to_hash(*args)
    
    # find the permission (and associated roles)
    permission = Permission.find(:first, :include => :roles, :conditions => {
      :controller_action => hash[:action],
      :controller_name   => hash[:controller]
    })
    
    # if the route is unprotected (no permission found)
    # then return false -- an empty list would mean
    # the route IS protected but no roles are configured
    if permission.nil?
      return false
    end
    
    # if the route is protected then return a list
    # of enabled roles (those allowed to access a route)
    # it is acceptable for this to be empty
    return permission.roles.select { |r| r.enabled? }
  end
  
  private

  # Convert arguments into a hash (in preparation for the roles_for_path)
  #
  def args_to_hash(*args)
    # The first argument may be a hash, if it is use it as-is
    # { :controller => 'admin', :action => 'index' }
    #
    if Hash === args[0]
      return args[0]
    end

    # The first argument is a url or path, ie:
    #  http://something.com/controller/action
    #  /controller/action....
    #
    if String === args[0]
      path = args[0]

      # If the path has a domain name and protocol
      # strip it off.
      if (!path.index('//').nil?)
        offset = path.index('/', path.index('//')+2)
        path = path[offset, path.length]
      end
    
      # Pull the HTTP method from the arguments, use :get
      # if none is found (for RESTful routes)
      method = (args[1] && args[1][:method]) || :get

      # generate a hash with controller, action, any id
      # to use for looking up permissions
      return ActionController::Routing::Routes.recognize_path(path, :method => method)
    end

    # If all else fails return an empty hash
    return {}
  end
  
end