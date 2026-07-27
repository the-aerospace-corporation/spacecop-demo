require 'openc3/microservices/microservice'
require 'openc3/utilities/sleeper'
require 'openc3/script'

module OpenC3
  class Cfdp < Microservice
    include Script

    def initialize(name)
      super(name)
      @target_name = "CFDP"
      @tlm_packet_name = "DOWNLINK_FILE_PKT"
      @cmd_packet_name = "UPLOAD_TO_SATELLITE_DATA"
      @period = 2  # 2 seconds
      @sleeper = Sleeper.new
      @chunk_size = 256
      @past_data_recv = ""
      @past_data_send = ""
      @sending = false
      @sending_num = 0
    end

    def run
      # Allow the other target processes to start before running the microservice
      @sleeper.sleep(@period)
      
      while true
        break if @cancel_thread
        
        begin
          data = tlm("#{@target_name} #{@tlm_packet_name} FILE_DATA")
          filename_dst = tlm("#{@target_name} #{@tlm_packet_name} FILENAME_DST")
          filename_src = tlm("#{@target_name} #{@tlm_packet_name} FILENAME_SRC")
          pdu = tlm("#{@target_name} #{@tlm_packet_name} PDU_TYPE")
          direction = tlm("#{@target_name} #{@tlm_packet_name} DIRECTION")
          
          if !filename_dst.nil? && !filename_src.nil?
            if pdu != 2
              # Direction 1: Receiving from satellite
              if direction == 1
                if @past_data_recv != data
                  if !data.nil? && data != ""
                    file_path = File.join("/received_files", filename_dst.strip)
                    
                    if data.is_a?(String)
                      @logger.info("Data received: #{data} with type: #{data.class}")
                      File.open(file_path, "ab") do |f|
                        f.write(data)
                      end
                    else
                      @logger.info("Length of Data received: #{data.length}")
                      File.open(file_path, "ab") do |f|
                        f.write(data)
                      end
                    end
                    @past_data_recv = data
                  end
                end
              end
              
              # Direction 2: Sending to satellite
              if direction == 2
                @sending_num = 0
                @sending = true
                file_path = File.join("/send_files", filename_dst.strip)
                
                File.open(file_path, "rb") do |file|
                  while @sending
                    data = file.read(@chunk_size)
                    
                    if data
                      # Convert bytes to hex string
                      hex_data = data.unpack1('H*')
                      bytes_read = hex_data.length
                      
                      if @past_data_send != hex_data
                        @logger.info("Sent #{@past_data_send} which is different than #{hex_data}")
                        cmd("#{@target_name} #{@cmd_packet_name} with LENGTH #{bytes_read}, PDU 1, DESTINATION '#{filename_src}', FILE_DATA '#{hex_data}'")
                        @logger.info("#{@sending_num}: Sending #{hex_data} to SC")
                        sleep(5)
                        @sending_num += 1
                        @past_data_send = hex_data
                      end
                    else
                      @sending = false
                    end
                  end
                end
                
                @logger.info("Sending EOF to SC")
                cmd("#{@target_name} #{@cmd_packet_name} with LENGTH 0, PDU 2, DESTINATION #{filename_src}, FILE_DATA ''")
                set_tlm("#{@target_name} #{@tlm_packet_name} DIRECTION = 99")
                @logger.info("File #{filename_dst} uploaded")
              end
            elsif direction != 99
              set_tlm("#{@target_name} #{@tlm_packet_name} DIRECTION = 99")
              @logger.info("File #{filename_dst} downloaded")
            end
          end
          
        rescue => e
          @logger.error("Error in CFDP microservice: #{e.message}")
          @logger.error(e.backtrace.join("\n"))
        end
        
        @sleeper.sleep(0.1)  # Small sleep to prevent tight loop
      end
    end

    def shutdown
      @sleeper.cancel  # Breaks out of run()
      super()
    end
  end
end

# Run the microservice
OpenC3::Cfdp.run if __FILE__ == \$0
