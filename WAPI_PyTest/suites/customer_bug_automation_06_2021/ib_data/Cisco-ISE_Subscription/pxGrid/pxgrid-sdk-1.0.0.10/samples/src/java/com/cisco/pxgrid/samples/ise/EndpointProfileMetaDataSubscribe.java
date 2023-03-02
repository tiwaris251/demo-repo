package com.cisco.pxgrid.samples.ise;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cisco.pxgrid.GridConnection;
import com.cisco.pxgrid.ReconnectionManager;
import com.cisco.pxgrid.TLSConfiguration;
import com.cisco.pxgrid.model.ise.metadata.EndpointProfile;
import com.cisco.pxgrid.model.ise.metadata.EndpointProfileChangedNotification;
import com.cisco.pxgrid.stub.isemetadata.EndpointProfileClientStub;
import com.cisco.pxgrid.stub.isemetadata.EndpointProfileNotification;

public class EndpointProfileMetaDataSubscribe {

	protected static final Logger log = LoggerFactory.getLogger(EndpointProfileMetaDataQuery.class);

	public static void main(String[] args)
		throws Exception
	{
		// collect command line parameters using helper class. custom implementations
		// will likely gather this information from a source other than command line.

		SampleProperties props = SampleProperties.load();
		SampleParameters params = new SampleParameters(props);
		params.appendCommonOptions();

		CommandLine line = null;
		try {
			line = params.process(args);
		} catch (IllegalArgumentException e) {
			params.printHelp("deviceprofilequery");
			System.exit(1);
		} catch (ParseException e) {
			params.printHelp("deviceprofilequery");
			System.exit(1);
		}

		String[] hostnames = params.retrieveHostnames(line);
		String username = params.retrieveUsername(line);
		String keystoreFilename = params.retrieveKeystoreFilename(line);
		String keystorePassword = params.retrieveKeystorePassword(line);
		String truststoreFilename = params.retrieveTruststoreFilename(line);
		String truststorePassword = params.retrieveTruststorePassword(line);

		System.out.println("------- properties -------");
		System.out.println("version=" + props.getVersion());
		System.out.println("hostnames=" + SampleUtilities.hostnamesToString(hostnames));
		System.out.println("username=" + username);
		System.out.println("keystoreFilename=" + keystoreFilename);
		System.out.println("keystorePassword=" + keystorePassword);
		System.out.println("truststoreFilename=" + truststoreFilename);
		System.out.println("truststorePassword=" + truststorePassword);
		System.out.println("--------------------------");


		// check keystore

		if (!SampleUtilities.isValid(keystoreFilename, keystorePassword)) {
			System.err.println("unable to read keystore. please check the keystore filename and keystore password.");
			System.exit(1);
		}

		// check truststore

		if (!SampleUtilities.isValid(truststoreFilename, truststorePassword)) {
			System.err.println("unable to read truststore. please check the truststore filename and truststore password.");
			System.exit(1);
		}

		// assemble configuration
		TLSConfiguration config = new TLSConfiguration();
		config.setHosts(hostnames);
		config.setUserName(username);
		//config.setGroup(Group.EPS.value());
		config.setKeystorePath(keystoreFilename);
		config.setKeystorePassphrase(keystorePassword);
		config.setTruststorePath(truststoreFilename);
		config.setTruststorePassphrase(truststorePassword);


		// initialize pxgrid connection

		GridConnection con = new GridConnection(config);
		con.addListener(new SampleConnectionListener());


		// use reconnection manager to ensure connection gets re-established
		// if dropped. this technique is recommended.

		ReconnectionManager recon = new ReconnectionManager(con);
		recon.setRetryMillisecond(2000);
		recon.start();


		// create query we'll use to make call

		EndpointProfileClientStub stub = new EndpointProfileClientStub(con);
		stub.registerNotification(new SampleNotificationCallback());
		

		// receive notifications until user presses <enter>

		System.out.println("press <enter> to disconnect...");
		System.in.read();


		// disconnect from pxGrid. with reconnection manager enabled we only need to call stop.

		recon.stop();
	}

	
	public static class SampleNotificationCallback implements EndpointProfileNotification
	{
		@Override
		public void handle(EndpointProfileChangedNotification notif) {
			EndpointProfile dp = notif.getEndpointProfile();
			System.out.println("EndpointProfileChangedNotification (changetype=" + notif.getChangeType() + ") Device profile : id="
					+ dp.getId() + ", name=" +
					dp.getName() + ", fqname=" + dp.getFqname());
					
		}
	}
}