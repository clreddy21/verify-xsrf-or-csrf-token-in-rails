# To be included in application controller


  def verify_request

    begin
      encoded_masked_token = cookies["XSRF-TOKEN"]
      masked_token = Base64.strict_decode64(encoded_masked_token)
      puts AUTHENTICITY_TOKEN_LENGTH
      one_time_pad = masked_token[0...AUTHENTICITY_TOKEN_LENGTH]
      encrypted_csrf_token = masked_token[AUTHENTICITY_TOKEN_LENGTH..-1]
      unmasked_token = xor_byte_strings(one_time_pad, encrypted_csrf_token)

      a = unmasked_token
      bb = real_csrf_token(session)
      a.bytesize == bb.bytesize
      l = a.unpack "C#{a.bytesize}"
      res = 0
      bb.each_byte { |byte| res |= byte ^ l.shift }
      raise(ActionController::InvalidAuthenticityToken) unless res == 0
    rescue
      raise(ActionController::InvalidAuthenticityToken)
    end
  end
