require 'uri'
require 'net/http'

module CMUX
  module Commands
    # Rolling refresh roles
    class RollingRefreshRoles < RollingRestart
      # Command properties.
      CMD   = 'refresh-datanodes'.freeze
      ALIAS = 'rd'.freeze
      DESC  = 'Refresh datanodes (with restart nodemanager)'.freeze

      # Regist command
      reg_cmd(cmd: CMD, alias: ALIAS, desc: DESC)

      # Run command
      def process
        super
        role_type = select_role_type
        roles     = select_role(role_type)
        print_the_selection(role_type, roles)
        #set_batch_execution_condition
        #rolling_restart(role_type, roles)

        refresh_datanodes(role_type, roles)
      end

      private

      LABEL = %I[cm cl cl_disp serviceType roleType cdh_ver serviceName].freeze

      def select_role_type
        cm, cl = select_cl('REFRESH DATANODE').values_at(0, 1)
        title  = "REFRESH DATANODE\n" \
                 "  * Cloudera Manager : #{cm}\n\n" \
                 "Select the ROLE TYPE :\n".red
        hosts  = CM.hosts(cm).select { |host| host[:cl] == cl }
        table  = build_role_type_table(hosts)
        fzfopt = "+m --with-nth=3..-3 --header='#{title}' --no-clear"

        selected = Utils.fzf(list: table, opt: fzfopt)
        Utils.exit_if_empty(selected, 'No items selected')
        selected.flat_map(&:split)
      end

      # Build CMUX table
      def build_role_type_table(hosts)
        header = TABLE_HEADERS.values_at(*LABEL)
        body   = hosts.flat_map do |host|
          roles = host[:roles].select { |_, r| r[:roleType] == 'DATANODE' }
          roles.values.map do |role|
            [host.values_at(*LABEL), role.values_at(*LABEL)]
              .transpose.map(&:compact).flatten
          end
        end
        Utils.exit_if_empty(body, 'Empty Roles')
        body.uniq!.sort_by! { |e| e.map(&:djust) }
        FMT.table(header: header, body: body)
      end

      def build_opts
        opt = CHK::OptParser.new
        opt.banner(CMD, ALIAS)
        opt.separator('Options:')
        opt.sync_option
        opt.help_option
        opt.parse
      end

      # Select role to rolling restart
      def select_role(role_type)
        cm, cl, cl_disp, s_type, r_type, _, service = role_type

        title = "REFRESH DATANODES\n" \
                "  * Cloudera Manager : #{cm}\n" \
                "  * Cluster          : [#{cl}] #{cl_disp}\n" \
                "  * Service type     : #{s_type}\n" \
                "  * Role type        : #{r_type}\n\n"

        title  = "#{title}Select ROLE(s) :\n".red
        header = ['Role Type', 'Role Type(short)', 'Hostname', 'Rolename', 'Rolename(NM)']
        hosts  = CM.hosts.select { |host| host[:cm] == cm }
        body   = hosts.flat_map do |host|
          nm_rolename = host[:roles].select do |_, r_props|
            host[:cl] == cl && r_props[:roleType] == 'NODEMANAGER'
          end.keys.first
          roles = host[:roles].select do |_, r_props|
            host[:cl] == cl && r_props[:roleType] == r_type
          end
          roles.map do |r, r_props|
            [r_type, r_props[:roleSType], host[:hostname], r, nm_rolename]
          end
        end
        body.sort_by! { |e| e.map(&:djust) }

        table  = FMT.table(header: header, body: body)
        fzfopt = "--with-nth=2.. --header='#{title}'"

        selected = Utils.fzf(list: table, opt: fzfopt)
        Utils.exit_if_empty(selected, 'No items selected')
        selected.map(&:split)
      rescue CMUXNameServiceError, CMUXNameServiceHAError => err
        print_the_selection(role_type, [])
        Utils.exit_with_msg("[#{cm}] #{cl}: #{err.message}".red, false)
      end

      # Print selected roles
      def print_the_selection(role_type, roles)
        cm, cl, cl_disp, s_type, r_type, cdh_ver, service = role_type

        puts 'Refresh datanodes'.red
        FMT.horizonal_splitter('-')

        print_cluster(cm, cl, cl_disp, cdh_ver)
        print_service(s_type, service)
        print_hbase_manager(cm, cl, cdh_ver)
        print_role_type(r_type)
        print_roles(cm, cl, roles)

        FMT.horizonal_splitter('-')
      end

      # Perform rolling restart
      def refresh_datanodes(role_type, roles)
        #value = CMUX::Utils.qna(roles.to_s.cyan, true)
        cm, cl, cl_disp, s_type, r_type, cdh_ver, service = role_type
        #cm, cl, r_type = role_type.values_at(0, 1, 4)
        begin
          roles.each.with_index(1) do |r, idx|
            hostname, role, nm_role = r.values_at(2, 3, 4)
            # Print 'refresh' message of the role
            msg = 'Refresh '.red + "[#{hostname}] #{role} (At first, stop #{nm_role})".yellow
            FMT.puts_str(msg, true)

            #if CHK.yn?('Continue (y|n:stop)? '.cyan, true)
            url_for_nm = create_api_url(cm, cl, nm_role.split('-NODEMANAGER-').first)
            url_for_dn = create_api_url(cm, cl, service)

            decommission_role(url_for_nm, nm_role)
            get_and_modify_config_dn(url_for_dn, role, 'dfs_data_dir_list')
            refresh_dn(url_for_dn, role)
            recommission_role(url_for_nm, nm_role)
            #else
            #  Utils.exit_with_msg('STOPPED'.red, true)
            #end
          end
        ensure
          finish_rolling_restart(cm, cl, r_type)
        end
      end

      def create_api_url(cm, cl, service)
        "http://#{cm}:7180/api/v19/clusters/#{cl}/services/#{service}"
      end

      def recommission_role(url, role)
        return unless CHK.yn?("Will you recommission/start #{role} (y|n:skip)? ".cyan, true)

        # recommission
        uri = URI("#{url}/commands/recommission")
        http_request(uri, :post, [role])
        puts "[ASYNC] Recommission #{role}".yellow

        # start
        uri = URI("#{url}/roleCommands/start")
        http_request(uri, :post, [role])
        puts "[ASYNC] Start #{role}".yellow
      end

      def decommission_role(url, role)
        return unless CHK.yn?("Will you decommission #{role} (y|n:skip)? ".cyan, true)

        uri = URI("#{url}/commands/decommission")
        http_request(uri, :post, [role])
        puts "[ASYNC] Decommission #{role}".yellow
      end

      def get_and_modify_config_dn(url, role, conf_key)
        uri = URI("#{url}/roles/#{role}/config")

        items = http_request(uri, :get)
        value = items.select { |item| item[:name] == conf_key }.first[:value]

        puts "#{conf_key} = #{value}"
        msg = "Enter a value to change : "
        new_value = CMUX::Utils.qna(msg.cyan, true)
        puts "\nEntered value = " + "#{new_value}".cyan
        get_and_modify_config_dn(url, role, conf_key) unless
          CHK.yn?('Continue to change (y|n:stop)? '.cyan, true)

        to_change = { name: 'dfs_data_dir_list', value: new_value.strip }
        http_request(uri, :put, [to_change])
      end

      def refresh_dn(url, role)
        uri = URI("#{url}/roleCommands/refresh")
        http_request(uri, :post, [role])
        puts "[ASYNC] Refresh #{role}".yellow
      end

      def http_request(uri, method, body = nil)
        req = case method.to_s
              when 'get'
                Net::HTTP::Get.new uri
              when 'post'
                Net::HTTP::Post.new uri
              when 'put'
                Net::HTTP::Put.new uri
              end
        req.basic_auth 'hadoop', 'qwerty123456'
        if body
          req.content_type = 'application/json'
          data = {}
          data[:items] = body
          req.body = data.to_json
        end
        res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request req }
        raise(StandardError, "#{res.code} #{res.message}") if res.code[0].to_i >= 4
        JSON.parse(res.body, symbolize_names: true)[:items]
      end
    end
  end
end
