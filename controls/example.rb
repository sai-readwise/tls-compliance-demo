# encoding: utf-8

control 'tls' do
  # Description of this test suite. Will be included in the test result report.
  title 'TLS compliance for web apps'
  desc 'Verifies that a web app complies with our published TLS standards.'

  # Read the value of the 'host_pairs' property provided via the inputs.yml file
  # or via the command-line arguments
  host_pairs = input('host_pairs')

  host_pairs.each do |host_pair|
    target_host = host_pair['host']
    target_port = host_pair['port']

    describe host(target_host, port: target_port, protocol: 'tcp') do
      it { should be_reachable }
      it { should be_resolvable }
      its('connection') { should_not match /connection refused/ }
    end
    
    # Disallow vulnerable or deprecated protocols
    describe ssl(host: target_host, port: target_port).protocols('ssl2') do
      it { should_not be_enabled }
    end
    
    describe ssl(host: target_host, port: target_port).protocols('ssl3') do
      it { should_not be_enabled }
    end
    
    describe ssl(host: target_host, port: target_port).protocols('tls1.0') do
      it { should_not be_enabled }
    end
    
    describe ssl(host: target_host, port: target_port).protocols('tls1.1') do
      it { should_not be_enabled }
    end
    
    # Mandate strong protocols
    describe ssl(host: target_host, port: target_port).protocols('tls1.2') do
      it { should be_enabled }
    end
    
    # Disallow weak ciphers
    describe ssl(host: target_host, port: target_port).ciphers('/ANON_WITH/i') do
      it { should_not be_enabled }
    end
    
    describe ssl(host: target_host, port: target_port).ciphers('/WITH_NULL/i') do
      it { should_not be_enabled }
    end

    describe ssl(host: target_host, port: target_port).ciphers('/_NULL$/i') do
      it { should_not be_enabled }
    end
    
    describe ssl(host: target_host, port: target_port).ciphers('/_WITH_EXPORT/i') do
      it { should_not be_enabled }
    end
    
    describe ssl(host: target_host, port: target_port).ciphers('/_WITH_RC4/i') do
      it { should_not be_enabled }
    end
    
    describe ssl(host: target_host, port: target_port).ciphers('/_WITH_(\d*)(des)/i') do
      it { should_not be_enabled }
    end

    describe ssl(host: target_host, port: target_port).ciphers('/WITH_CAMELLIA/i') do
      it { should_not be_enabled }
    end

    describe ssl(host: target_host, port: target_port).ciphers('/_MD5$/i') do
      it { should_not be_enabled }
    end

    describe ssl(host: target_host, port: target_port).ciphers('/_SHA$/i') do
      it { should_not be_enabled }
    end

    describe ssl(host: target_host, port: target_port).ciphers('/^TLS_GOSTR/i') do
      it { should_not be_enabled }
    end

    describe ssl(host: target_host, port: target_port).ciphers('/^TLS_DH/i') do
      it { should_not be_enabled }
    end

    # Mandate strong ciphers
    describe ssl(host: target_host, port: target_port).ciphers('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384') do
      it { should be_enabled }
    end

    describe ssl(host: target_host, port: target_port).ciphers('TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256') do
      it { should be_enabled }
    end
  end
end
