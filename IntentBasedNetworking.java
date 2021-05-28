/*
 * Copyright 2014 Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mx.itesm.intentBasedNetworking;
import com.google.common.collect.ImmutableSet;
import org.onlab.packet.Ethernet;
import org.onlab.packet.ICMP;
import org.onlab.packet.ICMP6;
import org.onlab.packet.IPv4;
import org.onlab.packet.IPv6;
import org.onlab.packet.Ip4Prefix;
import org.onlab.packet.Ip6Prefix;
import org.onlab.packet.MacAddress;
import org.onlab.packet.TCP;
import org.onlab.packet.TpPort;
import org.onlab.packet.UDP;
import org.onlab.packet.VlanId;
import org.onlab.util.KryoNamespace;
import org.onlab.util.Tools;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.event.Event;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.link.LinkEvent;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;
import org.onosproject.store.service.EventuallyConsistentMap;
import org.onosproject.store.service.MultiValuedTimestamp;
import org.onosproject.store.service.StorageService;
import org.onosproject.store.service.WallClockTimestamp;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;

import java.util.Dictionary;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.onlab.util.Tools.groupedThreads;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.FLOW_PRIORITY;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.FLOW_PRIORITY_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.FLOW_TIMEOUT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.FLOW_TIMEOUT_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.IGNORE_IPV4_MCAST_PACKETS;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.IGNORE_IPV4_MCAST_PACKETS_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.IPV6_FORWARDING;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.IPV6_FORWARDING_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_DST_MAC_ONLY;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_DST_MAC_ONLY_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_ICMP_FIELDS;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_ICMP_FIELDS_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV4_ADDRESS;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV4_ADDRESS_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV4_DSCP;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV4_DSCP_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV6_ADDRESS;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV6_ADDRESS_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV6_FLOW_LABEL;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_IPV6_FLOW_LABEL_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_TCP_UDP_PORTS;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_TCP_UDP_PORTS_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_VLAN_ID;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.MATCH_VLAN_ID_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.PACKET_OUT_OFPP_TABLE;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.PACKET_OUT_OFPP_TABLE_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.PACKET_OUT_ONLY;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.PACKET_OUT_ONLY_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.RECORD_METRICS;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.RECORD_METRICS_DEFAULT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.INHERIT_FLOW_TREATMENT;
import static mx.itesm.intentBasedNetworking.OsgiPropertyConstants.INHERIT_FLOW_TREATMENT_DEFAULT;
import static org.slf4j.LoggerFactory.getLogger;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.constraint.BandwidthConstraint;
import org.onosproject.net.intent.constraint.LatencyConstraint;
import java.util.LinkedList;
import org.onlab.util.Bandwidth;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
/**
 * Intent based networking
 */


import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.intent.Key;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.OutboundPacket;


import java.util.EnumSet;
import java.util.Set;


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.onlab.packet.Ethernet;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.HostToHostIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.IntentState;
import org.onosproject.net.intent.Key;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;


//para la ip
import org.onosproject.net.DeviceId;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.TCP;
import org.onlab.packet.UDP;

//listas
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;

//para hardtimeout e idle timeout
import org.onosproject.net.flow.FlowRule;
//para obtener bandwidth
import org.onosproject.net.config.basics.BasicLinkConfig;
import org.onosproject.net.LinkKey;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.ElementId;
//import org.onosproject.net.PortNumber;


//traffic engineering
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

//trafficengineering GET web
import javax.ws.rs.*;
//import javax.ws.rs.Path; ////////////////////////////////////////////////////////////////
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


//trafficengineering 
import org.onlab.graph.ScalarWeight;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.statistic.PortStatisticsService;
import org.onosproject.net.flow.*;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.*;
import org.onosproject.net.intent.util.IntentFilter;
import org.onosproject.net.provider.ProviderId;
import org.onosproject.net.topology.PathService;
import org.onosproject.rest.AbstractWebResource;
import org.onosproject.net.link.*;
import org.onosproject.net.*;

import org.slf4j.LoggerFactory;
import org.slf4j.Logger;

import java.io.InputStream;
//import java.util.ArrayList;
import java.util.Iterator;
//import java.util.List;
//aqui acaba traffic engineering

//read response
import com.fasterxml.jackson.databind.JsonNode;


// HTTP CLIENT TEST
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


//ARRAYS
import java.util.Arrays;

import java.util.EnumSet;

import static org.slf4j.LoggerFactory.getLogger;

//PARA EL TIMER Y SACAR DEL HASH
import java.util.Timer;
import java.util.TimerTask;

import org.onlab.packet.IpAddress;

import java.io.File;  // Import the File class
import java.io.IOException;  // Import the IOException class to handle errors
import java.io.Writer;
import java.io.PrintWriter;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



@Component(immediate = true)
public class intentBasedNetworking extends AbstractWebResource {

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected StorageService storageService;

    // Intent based networking


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    private static final int DROP_RULE_TIMEOUT = 30;

    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
                                                                            IntentState.WITHDRAWING,
                                                                            IntentState.WITHDRAW_REQ);
    //////////////

//////////////////////////MODIFICACIONES MARCELO /////////////////////////////////////

////////////////////
    private static final DeviceId mirrorDeviceID = DeviceId.deviceId("of:0000000000000065");
    private PortNumber mirrorPortNumber = PortNumber.portNumber(1);  // can change
    private static final PortNumber PktCollectorPortNumber = PortNumber.portNumber(1); // port to which the flow collector is connected to
    private static final PortNumber testingPort = PortNumber.portNumber(7); // eliminate

    // private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
    //                                                                         IntentState.WITHDRAWING,
    //                                                                         IntentState.WITHDRAW_REQ);
    //////////////
 
 ///////////////////////MODIFICACIONES MARCELO ///////////////////////////////////////   


    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    private  EventuallyConsistentMap<MacAddress, ReactiveForwardMetrics> metrics;

    private ApplicationId appId;

    /** Enable packet-out only forwarding; default is false. */
    private boolean packetOutOnly = PACKET_OUT_ONLY_DEFAULT;

    /** Enable first packet forwarding using OFPP_TABLE port instead of PacketOut with actual port; default is false. */
    private boolean packetOutOfppTable = PACKET_OUT_OFPP_TABLE_DEFAULT;

    /** Configure Flow Timeout for installed flow rules; default is 10 sec. */
    private int flowTimeout = FLOW_TIMEOUT_DEFAULT;

    /** Configure Flow Priority for installed flow rules; default is 10. */
    private int flowPriority = FLOW_PRIORITY_DEFAULT;

    /** Enable IPv6 forwarding; default is false. */
    private boolean ipv6Forwarding = IPV6_FORWARDING_DEFAULT;

    /** Enable matching Dst Mac Only; default is false. */
    private boolean matchDstMacOnly = MATCH_DST_MAC_ONLY_DEFAULT;

    /** Enable matching Vlan ID; default is false. */
    private boolean matchVlanId = MATCH_VLAN_ID_DEFAULT;

    /** Enable matching IPv4 Addresses; default is false. */
    private boolean matchIpv4Address = MATCH_IPV4_ADDRESS_DEFAULT;

    /** Enable matching IPv4 DSCP and ECN; default is false. */
    private boolean matchIpv4Dscp = MATCH_IPV4_DSCP_DEFAULT;

    /** Enable matching IPv6 Addresses; default is false. */
    private boolean matchIpv6Address = MATCH_IPV6_ADDRESS_DEFAULT;

    /** Enable matching IPv6 FlowLabel; default is false. */
    private boolean matchIpv6FlowLabel = MATCH_IPV6_FLOW_LABEL_DEFAULT;

    /** Enable matching TCP/UDP ports; default is false. */
    private boolean matchTcpUdpPorts = MATCH_TCP_UDP_PORTS_DEFAULT;

    /** Enable matching ICMPv4 and ICMPv6 fields; default is false. */
    private boolean matchIcmpFields = MATCH_ICMP_FIELDS_DEFAULT;

    /** Ignore (do not forward) IPv4 multicast packets; default is false. */
    private boolean ignoreIPv4Multicast = IGNORE_IPV4_MCAST_PACKETS_DEFAULT;

    /** Enable record metrics for reactive forwarding. */
    private boolean recordMetrics = RECORD_METRICS_DEFAULT;

    /** Enable use of builder from packet context to define flow treatment; default is false. */
    private boolean inheritFlowTreatment = INHERIT_FLOW_TREATMENT_DEFAULT;

    private final TopologyListener topologyListener = new InternalTopologyListener();

    private ExecutorService blackHoleExecutor;




 /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //hashmap to store important info about possible malicious
    private static HashMap<String, List<String>> hashPossibleMalicious = new HashMap<String, List<String>>();
    private static List<String> values = new ArrayList<String>();
    private int vecesEntro = 0;
    private static boolean flag = false;
    private static Timer timerHash = new Timer();
    private static TimerTask timerTask;
    private static long timeoutHashMap = 30_000; // milliseconds
    private boolean isEndDevice = false;
    private static HashMap<String, Integer> suspiciousTimes = new HashMap<String, Integer>();
    private static int totalFlows = 0;
    private static int totalMaliciousFlows = 0;
    private static int legitimateFlowsDropped = 0;
    private static int maliciousFlowsNotDropped = 0;
    private static int normalFlows = 0;
    private static int maliciousFlows = 0;
    private static int maliciousFlowsDropped = 0;
    //private static PrintWriter resultsFile = new PrintWriter("results.txt", "UTF-8");
    // /** Enable use of builder from packet context to define flow treatment; default is false. */
    // static final boolean INHERIT_FLOW_TREATMENT_DEFAULT = false;
    // private boolean inheritFlowTreatment = INHERIT_FLOW_TREATMENT_DEFAULT;
    
    // /** Configure Flow Timeout for installed flow rules; default is 10 sec. */
    // static final int FLOW_TIMEOUT_DEFAULT = 10;
    // private int flowTimeout = FLOW_TIMEOUT_DEFAULT;

    // /** Configure Flow Priority for installed flow rules; default is 10. */
    // static final int FLOW_PRIORITY_DEFAULT = 10;
    // private int flowPriority = FLOW_PRIORITY_DEFAULT;


 /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////   




    @Activate
    public void activate(ComponentContext context) {
        appId = coreService.registerApplication("mx.itesm.intentBasedNetworking");

        packetService.addProcessor(processor, PacketProcessor.director(2));
        topologyService.addListener(topologyListener);
        readComponentConfiguration(context);
        requestIntercepts();

        log.info("Started", appId.id());
    }

    @Deactivate
    public void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        withdrawIntercepts();
        flowRuleService.removeFlowRulesById(appId);
        packetService.removeProcessor(processor);
        topologyService.removeListener(topologyListener);
        //blackHoleExecutor.shutdown();
        blackHoleExecutor = null;
        processor = null;
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        readComponentConfiguration(context);
        requestIntercepts();
    }

    /**
     * Request packet in via packet service.
     */
    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        selector.matchEthType(Ethernet.TYPE_IPV6);
        if (ipv6Forwarding) {
            packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        } else {
            packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        }
    }

    /**
     * Cancel request for packet in via packet service.
     */
    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
        selector.matchEthType(Ethernet.TYPE_IPV6);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    /**
     * Extracts properties from the component configuration context.
     *
     * @param context the component context
     */
    private void readComponentConfiguration(ComponentContext context) {
        Dictionary<?, ?> properties = context.getProperties();

        Boolean packetOutOnlyEnabled =
                Tools.isPropertyEnabled(properties, PACKET_OUT_ONLY);
        if (packetOutOnlyEnabled == null) {
            log.info("Packet-out is not configured, " +
                     "using current value of {}", packetOutOnly);
        } else {
            packetOutOnly = packetOutOnlyEnabled;
            log.info("Configured. Packet-out only forwarding is {}",
                    packetOutOnly ? "enabled" : "disabled");
        }

        Boolean packetOutOfppTableEnabled =
                Tools.isPropertyEnabled(properties, PACKET_OUT_OFPP_TABLE);
        if (packetOutOfppTableEnabled == null) {
            log.info("OFPP_TABLE port is not configured, " +
                     "using current value of {}", packetOutOfppTable);
        } else {
            packetOutOfppTable = packetOutOfppTableEnabled;
            log.info("Configured. Forwarding using OFPP_TABLE port is {}",
                    packetOutOfppTable ? "enabled" : "disabled");
        }

        Boolean ipv6ForwardingEnabled =
                Tools.isPropertyEnabled(properties, IPV6_FORWARDING);
        if (ipv6ForwardingEnabled == null) {
            log.info("IPv6 forwarding is not configured, " +
                     "using current value of {}", ipv6Forwarding);
        } else {
            ipv6Forwarding = ipv6ForwardingEnabled;
            log.info("Configured. IPv6 forwarding is {}",
                    ipv6Forwarding ? "enabled" : "disabled");
        }

        Boolean matchDstMacOnlyEnabled =
                Tools.isPropertyEnabled(properties, MATCH_DST_MAC_ONLY);
        if (matchDstMacOnlyEnabled == null) {
            log.info("Match Dst MAC is not configured, " +
                     "using current value of {}", matchDstMacOnly);
        } else {
            matchDstMacOnly = matchDstMacOnlyEnabled;
            log.info("Configured. Match Dst MAC Only is {}",
                    matchDstMacOnly ? "enabled" : "disabled");
        }

        Boolean matchVlanIdEnabled =
                Tools.isPropertyEnabled(properties, MATCH_VLAN_ID);
        if (matchVlanIdEnabled == null) {
            log.info("Matching Vlan ID is not configured, " +
                     "using current value of {}", matchVlanId);
        } else {
            matchVlanId = matchVlanIdEnabled;
            log.info("Configured. Matching Vlan ID is {}",
                    matchVlanId ? "enabled" : "disabled");
        }

        Boolean matchIpv4AddressEnabled =
                Tools.isPropertyEnabled(properties, MATCH_IPV4_ADDRESS);
        if (matchIpv4AddressEnabled == null) {
            log.info("Matching IPv4 Address is not configured, " +
                     "using current value of {}", matchIpv4Address);
        } else {
            matchIpv4Address = matchIpv4AddressEnabled;
            log.info("Configured. Matching IPv4 Addresses is {}",
                    matchIpv4Address ? "enabled" : "disabled");
        }

        Boolean matchIpv4DscpEnabled =
                Tools.isPropertyEnabled(properties, MATCH_IPV4_DSCP);
        if (matchIpv4DscpEnabled == null) {
            log.info("Matching IPv4 DSCP and ECN is not configured, " +
                     "using current value of {}", matchIpv4Dscp);
        } else {
            matchIpv4Dscp = matchIpv4DscpEnabled;
            log.info("Configured. Matching IPv4 DSCP and ECN is {}",
                    matchIpv4Dscp ? "enabled" : "disabled");
        }

        Boolean matchIpv6AddressEnabled =
                Tools.isPropertyEnabled(properties, MATCH_IPV6_ADDRESS);
        if (matchIpv6AddressEnabled == null) {
            log.info("Matching IPv6 Address is not configured, " +
                     "using current value of {}", matchIpv6Address);
        } else {
            matchIpv6Address = matchIpv6AddressEnabled;
            log.info("Configured. Matching IPv6 Addresses is {}",
                    matchIpv6Address ? "enabled" : "disabled");
        }

        Boolean matchIpv6FlowLabelEnabled =
                Tools.isPropertyEnabled(properties, MATCH_IPV6_FLOW_LABEL);
        if (matchIpv6FlowLabelEnabled == null) {
            log.info("Matching IPv6 FlowLabel is not configured, " +
                     "using current value of {}", matchIpv6FlowLabel);
        } else {
            matchIpv6FlowLabel = matchIpv6FlowLabelEnabled;
            log.info("Configured. Matching IPv6 FlowLabel is {}",
                    matchIpv6FlowLabel ? "enabled" : "disabled");
        }

        Boolean matchTcpUdpPortsEnabled =
                Tools.isPropertyEnabled(properties, MATCH_TCP_UDP_PORTS);
        if (matchTcpUdpPortsEnabled == null) {
            log.info("Matching TCP/UDP fields is not configured, " +
                     "using current value of {}", matchTcpUdpPorts);
        } else {
            matchTcpUdpPorts = matchTcpUdpPortsEnabled;
            log.info("Configured. Matching TCP/UDP fields is {}",
                    matchTcpUdpPorts ? "enabled" : "disabled");
        }

        Boolean matchIcmpFieldsEnabled =
                Tools.isPropertyEnabled(properties, MATCH_ICMP_FIELDS);
        if (matchIcmpFieldsEnabled == null) {
            log.info("Matching ICMP (v4 and v6) fields is not configured, " +
                     "using current value of {}", matchIcmpFields);
        } else {
            matchIcmpFields = matchIcmpFieldsEnabled;
            log.info("Configured. Matching ICMP (v4 and v6) fields is {}",
                    matchIcmpFields ? "enabled" : "disabled");
        }

        Boolean ignoreIpv4McastPacketsEnabled =
                Tools.isPropertyEnabled(properties, IGNORE_IPV4_MCAST_PACKETS);
        if (ignoreIpv4McastPacketsEnabled == null) {
            log.info("Ignore IPv4 multi-cast packet is not configured, " +
                     "using current value of {}", ignoreIPv4Multicast);
        } else {
            ignoreIPv4Multicast = ignoreIpv4McastPacketsEnabled;
            log.info("Configured. Ignore IPv4 multicast packets is {}",
                    ignoreIPv4Multicast ? "enabled" : "disabled");
        }
        Boolean recordMetricsEnabled =
                Tools.isPropertyEnabled(properties, RECORD_METRICS);
        if (recordMetricsEnabled == null) {
            log.info("IConfigured. Ignore record metrics  is {} ," +
                    "using current value of {}", recordMetrics);
        } else {
            recordMetrics = recordMetricsEnabled;
            log.info("Configured. record metrics  is {}",
                    recordMetrics ? "enabled" : "disabled");
        }

        flowTimeout = Tools.getIntegerProperty(properties, FLOW_TIMEOUT, FLOW_TIMEOUT_DEFAULT);
        log.info("Configured. Flow Timeout is configured to {} seconds", flowTimeout);

        flowPriority = Tools.getIntegerProperty(properties, FLOW_PRIORITY, FLOW_PRIORITY_DEFAULT);
        log.info("Configured. Flow Priority is configured to {}", flowPriority);

        Boolean inheritFlowTreatmentEnabled =
                Tools.isPropertyEnabled(properties, INHERIT_FLOW_TREATMENT);
        if (inheritFlowTreatmentEnabled == null) {
            log.info("Inherit flow treatment is not configured, " +
                             "using current value of {}", inheritFlowTreatment);
        } else {
            inheritFlowTreatment = inheritFlowTreatmentEnabled;
            log.info("Configured. Inherit flow treatment is {}",
                     inheritFlowTreatment ? "enabled" : "disabled");
        }
    }

    /**
     * Packet processor responsible for forwarding packets along their paths.
     */
    private class ReactivePacketProcessor implements PacketProcessor {

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



   /**
     * Get bandwidth from all links and edges.
     *
     * @return 200 OK
     */
    // @GET
    // @Path("bandwidth/topology")
    // @Produces(MediaType.APPLICATION_JSON)
    public ObjectNode getTopologyBandwidth(String sourceAttacker, String destinationVictim) {
        
        LinkService linkService = get(LinkService.class);
        HostService hostService = get(HostService.class);
        PortStatisticsService portStatisticsService = get(PortStatisticsService.class);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        ArrayNode linksNode = mapper.createArrayNode();
        //probar con getlinks ya que se necesitan todos para buscar ruta mas corta
        for (Link link: linkService.getLinks()){
            //if para evitar obtener su link device 65 porque se usa para mirroring /////////////////////
            if( !link.src().deviceId().toString().equals("of:0000000000000065") && 
                !link.dst().deviceId().toString().equals("of:0000000000000065")) {
                long srcBw = portStatisticsService.load(link.src()).rate() * 8 / 1000;
                long dstBw = portStatisticsService.load(link.dst()).rate() * 8 / 1000;

                // unit: Kbps
                ObjectNode linkNode = mapper.createObjectNode()
                        .put("src", link.src().deviceId().toString())
                        .put("dst", link.dst().deviceId().toString())
                        .put("bw", (srcBw + dstBw) / 2 );   


                linksNode.add(linkNode);
            }
        }

        rootNode.set("links", linksNode);


        ArrayNode edgesNode = mapper.createArrayNode();
        //para sacar primero al atacante
        for (Host host: hostService.getHosts()){
             // unit: Kbps
            //guardar sourceAttacker y destination Victim en los edges para pasarlo al DIJKSTRA en python, 
            // solo mandar los datos del source attacker y de la victima
            //busca la ubicacion del src y su switch origen, y del dst y su switch origen
            String replaceHostID =  host.id().toString().replace("/None", ""); 

            if( sourceAttacker.equals( host.id().toString() ) ) {   

                ObjectNode hostNode = mapper.createObjectNode()
                        .put("host", host.id().toString())
                        .put("location", host.location().deviceId().toString())
                        .put("bw", portStatisticsService.load(host.location()).rate() * 8 / 1000);
                        // log.info( "hostttttttttt {} ", host.id().toString()  );
                        // log.info( "locationnnnnn {}", host.location().deviceId().toString());

                edgesNode.add(hostNode);
            }
        }
    //para sacar la victima al final
        for (Host host: hostService.getHosts()){
             // unit: Kbps
            //guardar sourceAttacker y destination Victim en los edges para pasarlo al DIJKSTRA en python, 
            // solo mandar los datos del source attacker y de la victima
            //busca la ubicacion del src y su switch origen, y del dst y su switch origen
            String replaceHostID =  host.id().toString().replace("/None", ""); 

            if( destinationVictim.equals( host.id().toString() ) ){   

                ObjectNode hostNode = mapper.createObjectNode()
                        .put("host", host.id().toString())
                        .put("location", host.location().deviceId().toString())
                        .put("bw", portStatisticsService.load(host.location()).rate() * 8 / 1000);
                        // log.info( "hostttttttttt {} ", host.id().toString()  );
                        // log.info( "locationnnnnn {}", host.location().deviceId().toString());

                edgesNode.add(hostNode);
            }
        }
        rootNode.set("edges", edgesNode);
        //log.info("Roooteeeeeeeeeeee Node\n {}",rootNode);

        //log.info("result {}",getTopologyBandwidth());

        return rootNode;

    }

/**
     * Get bandwidth from all links and edges.
     *
     * @return 200 OK
     */
    // @GET
    // @Path("installRule/ports")
    // @Produces(MediaType.APPLICATION_JSON)
    ///BORRAAAAAAAAAR DEL PACKETCONTEXT
    public void installRuleInSwitches(PortNumber sourcePortNumber, DeviceId sourceDeviceID , 
                            HostId hostsrcId, HostId hostdstId, boolean isEndDevice ) {
        
       //configuracion de switches para redirigir trafico
        //Ethernet inPkt = context.inPacket().parsed();
        // log.info("sourcePortNumber en INSTALLRULE   {} ",sourcePortNumber);
        // //log.info("destinationPortNumber en INSTALLRULE  {} ",destinationPortNumber);
        // log.info("contextINPACKET {}",  context.inPacket().receivedFrom().port() );
        // log.info("sourceMACINPACKET {}",  inPkt.getSourceMAC() );
        // log.info("destinationmacINPACKET {}",  inPkt.getDestinationMAC() );
        //
        TrafficTreatment treatment = null;  
        if( isEndDevice == false ){
            //log.info("Entra a treatment false  {}",isEndDevice);
                          
                treatment = DefaultTrafficTreatment.builder()
                        .setOutput(sourcePortNumber)
                        .build();       

        }
        else if( isEndDevice == true ) {
            log.info("Entra a treatment true  {}",isEndDevice);
            //TrafficTreatment treatment;          
                treatment = DefaultTrafficTreatment.builder()
                        .setOutput(sourcePortNumber)
                        .setOutput(mirrorPortNumber)
                        .build();    
        }
     

       // if (inheritFlowTreatment) {
       //      treatment = context.treatmentBuilder()
       //              .setOutput(destinationPortNumber)
       //              .build();
       //  } else {
       //      treatment = DefaultTrafficTreatment.builder()
       //              .setOutput(destinationPortNumber)
       //              .build();
       //  }


        // TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
        //                 .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

       
        TrafficSelector selectorBuilder = DefaultTrafficSelector.builder()
                .matchEthSrc(hostsrcId.mac()).matchEthDst(hostdstId.mac()).build();

        ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder)
                .withTreatment(treatment)
                .withPriority(120)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();

                //link.src().deviceId()

        flowObjectiveService.forward(sourceDeviceID,
                                     forwardingObjective);
       
       
    }





   /**
     * Get bandwidth from all links and edges.
     *
     * @return 200 OK
     */
    // @GET
    // @Path("switches/ports")
    // @Produces(MediaType.APPLICATION_JSON)
    public ObjectNode getSwitchesPorts(String switchesHop[], HostId hostsrcId, HostId hostdstId, String destinationMac) {
        
        LinkService linkService = get(LinkService.class);
        HostService hostService = get(HostService.class);
        PortStatisticsService portStatisticsService = get(PortStatisticsService.class);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();
        isEndDevice = false;
        ArrayNode linksNode = mapper.createArrayNode();
        for( int i = 0; i < switchesHop.length-1; i++ ){
            //probar con getLinks() para obtener todos los links y no solo los activos ya que necesitamos buscar por todos para los puertos
            for (Link link: linkService.getLinks()){                    
                //si el primer switch por el que hay que ir es igual al switch que se esta recorriendo
                //para obtener los puertos que conectan los switches por los que tiene que viajar el flujo
                if( switchesHop[i].contains( link.src().deviceId().toString() ) &&
                    switchesHop[i+1].contains( link.dst().deviceId().toString() ) ){

                    long srcBw = portStatisticsService.load(link.src()).rate() * 8 / 1000;
                    long dstBw = portStatisticsService.load(link.dst()).rate() * 8 / 1000;

                    // unit: Kbps
                    ObjectNode linkNode = mapper.createObjectNode()
                            .put("src", link.src().deviceId().toString())
                            .put("srcport", link.src().port().toString())
                            .put("dst", link.dst().deviceId().toString())
                            .put("dstport", link.dst().port().toString())
                            .put("bw", (srcBw + dstBw) / 2 );
                            //link.src().deviceId()
                    installRuleInSwitches(link.src().port(), link.src().deviceId() ,hostsrcId, hostdstId, isEndDevice);   


                    // log.info("SRC"+ link.src().deviceId().toString()  );
                    // log.info( "SRCPORT"+link.src().port().toString()   );                   
                    // log.info( "DST"+link.dst().deviceId().toString()   );
                    // log.info( "DSTPORT"+link.dst().port().toString()   );
                    linksNode.add(linkNode);

                }    
            }
            //para ir en la iteracion del ultimo
            if( i == switchesHop.length -2 ){
                ArrayNode edgesNode = mapper.createArrayNode();
                isEndDevice = true;
                for (Host host: hostService.getHosts()){
                    // unit: Kbps
                    //guardar sourceAttacker y destination Victim en los edges para pasarlo al DIJKSTRA en python, 
                    // solo mandar los datos del source attacker y de la victima
                    String replaceHostID =  host.id().toString().replace("/None", "");
                    //log.info( "HOSTIDDDDDDDDDD "+replaceHostID ); 
                    //log.info("Destination Mac   "+ destinationMac); 
                    if( host.location().deviceId().toString().equals( switchesHop[i+1]   ) &&
                        host.id().toString().equals( destinationMac ) ){   

                        ObjectNode hostNode = mapper.createObjectNode()
                                .put("host", host.id().toString())
                                .put("location", host.location().deviceId().toString())
                                .put("bw", portStatisticsService.load(host.location()).rate() * 8 / 1000);

                                log.info( "Host final "+host.id().toString()  );
                                // log.info( "Location host switch final "+host.location().deviceId().toString()  );
                                // log.info( "Puerto entre Host destino y Switch final "+host.location().port() );
                        //agregar variable tipo booleano
                        
                        installRuleInSwitches(host.location().port(), host.location().deviceId() ,hostsrcId, hostdstId, isEndDevice );

                        edgesNode.add(hostNode);
                        rootNode.set("edges", edgesNode);
                    }
                }

            }
        }
        //para obtener el puerto de [HostDestino con switchFinal]
        // Host hostDestination;
        // hostDestination.getLocation().deviceId(); //getport
        // link.src().port()
        // //puertoHost, ultimo deviceId
        // installRuleInSwitches(link.src().port(), link.src().deviceId() ,context);   

        rootNode.set("portsLinks", linksNode);

        return rootNode;

    }

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////        


        @Override
        public void process(PacketContext context) {
            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
/*
            if (context.isHandled()) {
                return;
            }
*/
            //mitigation();

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            MacAddress macAddress = ethPkt.getSourceMAC();
            ReactiveForwardMetrics macMetrics = null;
            macMetrics = createCounter(macAddress);
            inPacket(macMetrics);

            // Bail if this is deemed to be a control packet.
            if (isControlPacket(ethPkt)) {
                droppedPacket(macMetrics);
                return;
            }

            // Skip IPv6 multicast packet when IPv6 forward is disabled.
            if (!ipv6Forwarding && isIpv6Multicast(ethPkt)) {
                droppedPacket(macMetrics);
                return;
            }
       


            HostId id = HostId.hostId(ethPkt.getDestinationMAC(), VlanId.vlanId(ethPkt.getVlanID()));

            // Do not process LLDP MAC address in any way.
            if (id.mac().isLldp()) {
                droppedPacket(macMetrics);
                return;
            }

            // Do not process IPv4 multicast packets, let mfwd handle them
            if (ignoreIPv4Multicast && ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                if (id.mac().isMulticast()) {
                    return;
                }
            }

             //MITIGATIOOOOOOOOOON METHOD
            mitigation();

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(id);
            if (dst == null) {
                flood(context, macMetrics);
                return;
            }

            // Are we on the mirroring switch? If so,
            // simply forward out to the Packet Collector and bail.
            if (pkt.receivedFrom().deviceId().equals(mirrorDeviceID)) {
                //log.info("SW mirror: receivedFrom {}",context.inPacket().receivedFrom());
                if (!context.inPacket().receivedFrom().port().equals(PktCollectorPortNumber)) {
                    //installRuleFwd(context, PktCollectorPortNumber, macMetrics);
                    installRule(context, PktCollectorPortNumber, macMetrics, false);
                }
                return;
            }
        

            // Are we on an edge switch that our destination is on? If so,
            // simply forward out to the destination and bail.
            if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
                if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
                    installRule(context, dst.location().port(), macMetrics, true);
                }
                return;
            }

            // Otherwise, get a set of paths that lead from here to the
            // destination edge switch.
            Set<Path> paths =
                    topologyService.getPaths(topologyService.currentTopology(),
                                             pkt.receivedFrom().deviceId(),
                                             dst.location().deviceId());
            if (paths.isEmpty()) {
                // If there are no paths, flood and bail.
                flood(context, macMetrics);
                return;
            }

            // Otherwise, pick a path that does not lead back to where we
            // came from; if no such path, flood and bail.
            Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
            if (path == null) {
                log.warn("Don't know where to go from here {} for {} -> {}",
                         pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
                flood(context, macMetrics);
                return;
            }


           
           
                        // Otherwise forward and be done with it.
            installRule(context, path.src().port(), macMetrics, false);


        }


        private void mitigation(){

        //Comunicar con el IDS 
        //normal es default, en caso que ocurra error con ids, parseo, etc
        String resultIPS[] = {};
        String resultTAGS[] = {};
        String label = "normal";
        try {

            Client client = ClientBuilder.newClient();
            //String response = client.target("http://192.168.0.101:9001/predict").request().post(Entity.entity(jsonFlow1,MediaType.APPLICATION_JSON),String.class);
            String response = client.target("http://192.168.1.103:9001/respond").request().get(String.class);
            log.info("Response {}",response);

            ObjectMapper mapper = new ObjectMapper();
            InputStream stream = null;
            
            mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
            try{
                ObjectNode rootNode = mapper.createObjectNode();
                //stream = new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8));
                stream = org.apache.commons.io.IOUtils.toInputStream(response, "UTF-8");
                //log.info("Class stream "+stream.getClass());

                //ProviderId providerId = new ProviderId("provider.scheme", "provider.id");
                Map<String, Object> suspicious_ = mapper.readValue(stream, Map.class);
                //Routes routes = mapper.readValue(stream, Routes.class);
                //log.info("SUspicious size "+suspicious_.size());
                int sizeArrayIPData = suspicious_.size() *2;
                //X2 porque obtenemos 2 valores, iporigen-ipdestino
                resultIPS = new String[ sizeArrayIPData];
                //X2 porque obtenemos 2 valores, predlabel-reallabel 
                resultTAGS = new String[ sizeArrayIPData]; 
                
                if (suspicious_ == null || suspicious_.size() == 0) {
                    rootNode.put("response", "No given hosts to drop packets");
                    //log.info("response no given hosts detected");
                }
                int mapI = 0;
                String auxSplitIPS[] = {};
                String auxSplitTAGS[] = {};
                String auxReceiveKey;
                String auxReceiveValue;
                 for (Map.Entry<String, Object> entry : suspicious_.entrySet()) {
                    auxReceiveKey = "" + entry.getKey();
                    auxReceiveValue = "" + entry.getValue();
                    auxSplitIPS = auxReceiveKey.split("-");
                    auxSplitTAGS = auxReceiveValue.split("-");
                    resultIPS[ mapI ] = auxSplitIPS[0]; //iporigen
                    resultIPS[ mapI + 1 ] = auxSplitIPS[1]; //ipdestino
                    resultTAGS[ mapI ] =  auxSplitTAGS[0];  //predlabel
                    resultTAGS[ mapI + 1 ] =  auxSplitTAGS[1]; //reallabel
                    mapI  = mapI + 2;                  
                    // log.info("IPORIGEN-DESTINO {}",resultIPS);
                    // log.info("PRED-REAL {}",resultTAGS);
                }


            }catch(Exception e){
                log.info(e.toString());
  
            }                 
        

        } catch (Exception e) {
            log.error("Error communicating to IDS service.");
            //System.out.println ("Error communicating to IDS service.");
        }

        HostService hostService = get(HostService.class);
        HostId hostsrcId = null;
        HostId hostdstId = null;
        
        String hostSourceIP = "";
        String hostDestinationIP;
        
        String tagPred;
        String tagReal;
        if( resultIPS.length != 0){
            for(int r = 0 ; r < resultIPS.length -1 ; r++){
                log.info(" IP ORIGEN "+resultIPS[r]);
                log.info(" IP DESTINATION "+resultIPS[r+1]);
                log.info(" PREDICTED TAG "+resultTAGS[r]);
                log.info(" REAL TAG "+resultTAGS[r+1]);
                
                hostSourceIP = resultIPS[r];
                hostDestinationIP = resultIPS[r+1];

                tagPred = resultTAGS[r];
                tagReal = resultTAGS[r+1];

                Set<Host> hosts = hostService.getHostsByIp(IpAddress.valueOf(hostSourceIP));
                //if (hosts.isEmpty()) continue;
                for (Host host: hosts) {
                    hostsrcId = host.id();
                    //log.info("asfadfasdfasdfas {}",hostsrcId);
                }

                hosts = hostService.getHostsByIp(IpAddress.valueOf(hostDestinationIP));
                
                for (Host host: hosts) {
                    hostdstId = host.id();
                }


            //contar todos los flujos que llegan
            if( (tagPred.equals("normal") || !tagPred.equals("normal")) && tagPred != null ){
                totalFlows = totalFlows + 1;                
            }
            //contar los flujos malignos no dropeados
            if( !tagReal.equals("normal") && tagReal != null){
                maliciousFlowsNotDropped = maliciousFlowsNotDropped + 1;
            }
            //contar flujos normales
            if( tagReal.equals("normal") && tagReal != null){
                normalFlows = normalFlows + 1;
            }

            //contar los flujos malignos no dropeados
            if( !tagReal.equals("normal") && tagReal != null){
                maliciousFlows = maliciousFlows + 1;
            }
            

            //iniciar en 0 cuando llega un nuevo flujo sospechoso
            if( !suspiciousTimes.containsKey(hostSourceIP) && !tagPred.equals("normal") && tagPred != null){
                //0
                suspiciousTimes.put(hostSourceIP, 0 );
            }


            //AGREGAR TAMBIEN UN TIMEMILISECONDS PARA SACAR DEL HASH CADA CIERT TIEMPO LOS FLUJOS MALIGNOS Y NO SE QUEDEN EN MEMORIA

            //log.info("TAAGGGGG PREDDD {}",tagPred);
            //Si el flujo es atacante, y no esta en el hash
            //Redirigir a los canales menos usados en terminos de bandwidth, instalar reglas HARDTIMEOUT e IDLE
            if( !tagPred.equals("normal") && tagPred != null ){
                //log.info("The attacker is "+ethPkt.getSourceMAC().toString());
                log.info("The attacker IP is "+hostSourceIP);
                

                //obtiene el acumulado
                int auxSuspiciousTimes = suspiciousTimes.get(hostSourceIP);
                //al 0 obtenido le aumenta 1
                suspiciousTimes.put(hostSourceIP, auxSuspiciousTimes + 1 );




                //Agregar a hashmap, para que la 2da vez que pase sea mitigado
                vecesEntro = vecesEntro + 1;
                //log.info("vecesEntro "+vecesEntro);
                //ipdestino
                values.add(hostDestinationIP);
                //mac origen
                //values.add(ethPkt.getSourceMAC().toString());
                //mac destino
                //values.add(ethPkt.getDestinationMAC().toString());
                //puerto origen
                //values.add(""+srcport);
                //puerto destino
                //values.add(""+dstport);
                //colocar 1 vez agregado
                values.add("First time added");
                //la llave es la ip origen    
                hashPossibleMalicious.put(hostSourceIP, values);
                //log.info("SIZE "+hashPossibleMalicious.size());
                int i = 0;
                // to get the arraylist values of the given hashmap key
                for( String value : values) {
                    //System.out.println(""+i+" "+hm.get(srcips).get(i));
                    //log.info(""+i+" "+hashPossibleMalicious.get(srcips).get(i));
                    i++;
                }
               


                //AGREGAR PARTE DE CODIGO DE REDIRIGIR ESTE FLUJO MALIGNO A LOS CANALES MENOS USADOS

                //log.info(" SRCID "+ hostsrcId.toString() + " DESTID " + hostdstId.toString());
                //para mandar los links, edges, bw, de la topologia
                //mando la mac source del atacante y de la victima
                String jsonFlowGoing = "" + getTopologyBandwidth(hostsrcId.toString(), hostdstId.toString());
                String auxResponseGoing = "";
                // String jsonFlowBack = "" + getTopologyBandwidth( ethPkt.getDestinationMAC().toString() , ethPkt.getSourceMAC().toString());
                // String auxResponseBack = "";

                try {
                    Client client = ClientBuilder.newClient();
                    //String response = client.target("http://10.0.2.15:9001/predict").request().get(String.class);
                    String responseGoing = client.target("http://192.168.1.103:8081/shortestPath/").request().post(Entity.entity(jsonFlowGoing,MediaType.APPLICATION_JSON),String.class);
                    auxResponseGoing = responseGoing;
                    // String responseBack = client.target("http://192.168.1.103:8081/shortestPath/").request().post(Entity.entity(jsonFlowBack,MediaType.APPLICATION_JSON),String.class);
                    // auxResponseBack = responseBack;
                    //if (!responseGoing.equals("incomplete")){
                        log.info("Response from server responsegoing: {}",responseGoing);
                    //}
                    //else{
                        //log.info("No hay response de DIJKSTRA ");
                    //}
                    // if (!responseBack.equals("incomplete")){
                    //     log.info("Response from server responseback: {}",responseBack);
                    // }

                } catch (Exception e) {
                    log.error("Error talking to Classifier API.");
                }

                
                //log.info("getTopoBand {}",getTopologyBandwidth(  ethPkt.getSourceMAC().toString(), ethPkt.getDestinationMAC().toString()  ));
                String formatedResponseGoing = auxResponseGoing.replace("[", "").replace("]","").replace(",","").replace("\"", "");
                //String formatedResponseBack = auxResponseBack.replace("[", "").replace("]","").replace(",","").replace("\"", "");
                
                //si la longitud de la cadena es par, (longitud / 2) -1 = numSwitchesPorPasar
                int numSwitches = 0;

                String switchesHopGoing[] = formatedResponseGoing.split(" "); 
                log.info("Switches Going "+ Arrays.toString(switchesHopGoing)); 
                
                //log.info("Switches Back "+ Arrays.toString(switchesHopBack));  

                String switchesHopBack[] = new String[ switchesHopGoing.length ]; 
                //log.info("Length de switchesHOP {}", switchesHop.length );
                String prueba[] = new String[3];
                prueba[0] = "of:0000000000000002";
                prueba[1] = "of:0000000000000003";
                prueba[2] = "of:0000000000000001";
                

                int j = 0;
                //reversear un array para obtener el path de regreso 
                for(int a = switchesHopGoing.length-1 , b = 0; a >= 0 ; a--, b++ ){                    
                    switchesHopBack[b] = switchesHopGoing[a];
                    //log.info("sssssssssss {}",switchesHopBack[b]);
                }


                //obtiene los puertos de los switches por los que tiene que ir
                //y despues llama a una funcion para instalar las reglas

  
                getSwitchesPorts(switchesHopGoing, hostsrcId, hostdstId, hostdstId.toString());
                getSwitchesPorts(switchesHopBack, hostdstId, hostsrcId, hostsrcId.toString());
   
                //log.info("CONTIENE KEY? "+hashPossibleMalicious.containsKey(hostSourceIP));


                // String timeoutSourceIP = hostSourceIP;
                // //para que cada cierto tiempo se saque ese flujo sospechoso del hashmap
                // timerHash.schedule(new TimerTask() {
                //         @Override
                //         public void run() {
                //             hashPossibleMalicious.remove(timeoutSourceIP);
                //         }
                // }, timeoutHashMap);

                 log.info("NOT DROPPED "+hostSourceIP+ " "+ suspiciousTimes.get(hostSourceIP));
            }
            //Si el atacante ya esta en el hash, entonces mitigar ese flujo, en el switch mas cercano al atacante
            if( !tagPred.equals("normal")  && suspiciousTimes.get(hostSourceIP) == 3 && tagPred != null ){            
                log.info("DROPPED "+hostSourceIP+ " "+ suspiciousTimes.get(hostSourceIP));

                vecesEntro = 0;
                // // cortar trafico (ya funciona)
                TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(hostsrcId.mac()).matchEthDst(hostdstId.mac()).build();

                TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

                ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(150)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();


                flowObjectiveService.forward(hostService.getHost(hostsrcId).location().deviceId(), objective);

                String timeoutSourceIP = hostSourceIP;
                String auxHostSourceIP = hostSourceIP;

                suspiciousTimes.remove( hostSourceIP );

                // //para que cada cierto tiempo se saque ese flujo sospechoso del hashmap
                // timerHash.schedule(timerTask = new TimerTask() {
                //         @Override
                //         public void run() {
                //             hashPossibleMalicious.remove(timeoutSourceIP);
                //             suspiciousTimes.remove( auxHostSourceIP );
                //         }
                //     }, timeoutHashMap);
                //DROP_RULE_TIMEOUT

                //trafico normal dropeado
                if( tagReal.equals("normal")){
                    legitimateFlowsDropped = legitimateFlowsDropped + 1;                     

                }
                if(!tagReal.equals("normal")){
                    maliciousFlowsDropped = maliciousFlowsDropped + 1;
                }



            }


            log.info( "legitimateFlowsDropped: "+ legitimateFlowsDropped );
            log.info( "maliciousFlowsNotDropped: "+maliciousFlowsNotDropped);
            log.info( "maliciousFlowsDropped: "+maliciousFlowsDropped);
            log.info( "normalFlows: "+normalFlows);
            log.info( "maliciousFlows: "+maliciousFlows);
            log.info( "totalFlows: "+totalFlows );

            // try {  
            //     PrintWriter resultsFile = new PrintWriter("results.txt", "UTF-8");
            //     resultsFile.println("legitimateFlowsDropped: "+ legitimateFlowsDropped);
            //     resultsFile.println("maliciousFlowsNotDropped: "+maliciousFlowsNotDropped);
            //     resultsFile.println("totalFlows: "+totalFlows);
            //     resultsFile.close();
            // } catch (IOException e) {
            //     System.out.println("Results file error");
            //     e.printStackTrace();  
            // }




            }
        }
        else{
            log.info("Empty flowcollector ");
        }

    }

    }



    // Indicates whether this is a control packet, e.g. LLDP, BDDP
    private boolean isControlPacket(Ethernet eth) {
        short type = eth.getEtherType();
        return type == Ethernet.TYPE_LLDP || type == Ethernet.TYPE_BSN;
    }

    // Indicated whether this is an IPv6 multicast packet.
    private boolean isIpv6Multicast(Ethernet eth) {
        return eth.getEtherType() == Ethernet.TYPE_IPV6 && eth.isMulticast();
    }

    // Selects a path from the given set that does not lead back to the
    // specified port if possible.
    private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
        Path pathAvailable = null;
        PortNumber temporal = null;
        for (Path path : paths) {
            Boolean includeMirrorDevice = false;
            for (Link link:path.links()){
                if (link.dst().deviceId().equals(mirrorDeviceID)) { // avoid paths that pass to the mirrorring SW
                    includeMirrorDevice = true;
                    temporal = link.dst().port();
                }
            }
            if (path.dst().deviceId().equals(mirrorDeviceID) && path.links().size()==1){ // get port that connects to the mirroring device
                //mirrorPortNumber = temporal;
            }

            if (!path.src().port().equals(notToPort) && !includeMirrorDevice) { // do not return to the same port
                         pathAvailable = path;
            }
        }
        return pathAvailable;
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context, ReactiveForwardMetrics macMetrics) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                                             context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD, macMetrics);
        } else {
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber, ReactiveForwardMetrics macMetrics) {
        replyPacket(macMetrics);
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    // Install a rule forwarding the packet to the specified port.
    private void installRule(PacketContext context, PortNumber portNumber, ReactiveForwardMetrics macMetrics, Boolean endDevice) {
        //
        // We don't support (yet) buffer IDs in the Flow Service so
        // packet out first.
        //
        Ethernet inPkt = context.inPacket().parsed();
        TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();

        // If PacketOutOnly or ARP packet than forward directly to output port
        if (packetOutOnly || inPkt.getEtherType() == Ethernet.TYPE_ARP) {
            packetOut(context, portNumber, macMetrics);
            return;
        }

        //
        // If matchDstMacOnly
        //    Create flows matching dstMac only
        // Else
        //    Create flows with default matching and include configured fields
        //
        if (matchDstMacOnly) {
            selectorBuilder.matchEthDst(inPkt.getDestinationMAC());
        } else {
            selectorBuilder.matchInPort(context.inPacket().receivedFrom().port())
                    .matchEthSrc(inPkt.getSourceMAC())
                    .matchEthDst(inPkt.getDestinationMAC());

            // If configured Match Vlan ID
            if (matchVlanId && inPkt.getVlanID() != Ethernet.VLAN_UNTAGGED) {
                selectorBuilder.matchVlanId(VlanId.vlanId(inPkt.getVlanID()));
            }

            //
            // If configured and EtherType is IPv4 - Match IPv4 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv4Address && inPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ipv4Packet = (IPv4) inPkt.getPayload();
                byte ipv4Protocol = ipv4Packet.getProtocol();
                Ip4Prefix matchIp4SrcPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getSourceAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                Ip4Prefix matchIp4DstPrefix =
                        Ip4Prefix.valueOf(ipv4Packet.getDestinationAddress(),
                                          Ip4Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV4)
                        .matchIPSrc(matchIp4SrcPrefix)
                        .matchIPDst(matchIp4DstPrefix);

                if (matchIpv4Dscp) {
                    byte dscp = ipv4Packet.getDscp();
                    byte ecn = ipv4Packet.getEcn();
                    selectorBuilder.matchIPDscp(dscp).matchIPEcn(ecn);
                }

                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv4Protocol == IPv4.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv4Protocol == IPv4.PROTOCOL_ICMP) {
                    ICMP icmpPacket = (ICMP) ipv4Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv4Protocol)
                            .matchIcmpType(icmpPacket.getIcmpType())
                            .matchIcmpCode(icmpPacket.getIcmpCode());
                }
            }

            //
            // If configured and EtherType is IPv6 - Match IPv6 and
            // TCP/UDP/ICMP fields
            //
            if (matchIpv6Address && inPkt.getEtherType() == Ethernet.TYPE_IPV6) {
                IPv6 ipv6Packet = (IPv6) inPkt.getPayload();
                byte ipv6NextHeader = ipv6Packet.getNextHeader();
                Ip6Prefix matchIp6SrcPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getSourceAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                Ip6Prefix matchIp6DstPrefix =
                        Ip6Prefix.valueOf(ipv6Packet.getDestinationAddress(),
                                          Ip6Prefix.MAX_MASK_LENGTH);
                selectorBuilder.matchEthType(Ethernet.TYPE_IPV6)
                        .matchIPv6Src(matchIp6SrcPrefix)
                        .matchIPv6Dst(matchIp6DstPrefix);

                if (matchIpv6FlowLabel) {
                    selectorBuilder.matchIPv6FlowLabel(ipv6Packet.getFlowLabel());
                }

                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_TCP) {
                    TCP tcpPacket = (TCP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchTcpSrc(TpPort.tpPort(tcpPacket.getSourcePort()))
                            .matchTcpDst(TpPort.tpPort(tcpPacket.getDestinationPort()));
                }
                if (matchTcpUdpPorts && ipv6NextHeader == IPv6.PROTOCOL_UDP) {
                    UDP udpPacket = (UDP) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchUdpSrc(TpPort.tpPort(udpPacket.getSourcePort()))
                            .matchUdpDst(TpPort.tpPort(udpPacket.getDestinationPort()));
                }
                if (matchIcmpFields && ipv6NextHeader == IPv6.PROTOCOL_ICMP6) {
                    ICMP6 icmp6Packet = (ICMP6) ipv6Packet.getPayload();
                    selectorBuilder.matchIPProtocol(ipv6NextHeader)
                            .matchIcmpv6Type(icmp6Packet.getIcmpType())
                            .matchIcmpv6Code(icmp6Packet.getIcmpCode());
                }
            }
        }
       TrafficTreatment treatment;
        if (inheritFlowTreatment) {

            treatment = context.treatmentBuilder()
            .setOutput(portNumber)
            .build();
        } else {
            if(endDevice){
                treatment = context.treatmentBuilder()
                .setOutput(portNumber)
                .setOutput(mirrorPortNumber)
                .build();           
            }else{
                treatment = context.treatmentBuilder()
                .setOutput(portNumber)
                .build();
            }
        }

       ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
                .withSelector(selectorBuilder.build())
                .withTreatment(treatment)
                .withPriority(flowPriority)
                .withFlag(ForwardingObjective.Flag.VERSATILE)
                .fromApp(appId)
                .makeTemporary(flowTimeout)
                .add();
    

       flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(),
                                     forwardingObjective);
       forwardPacket(macMetrics);


//  INTENT BASED NETWORKING

       /* HostId srcId = HostId.hostId(inPkt.getSourceMAC());
        HostId dstId = HostId.hostId(inPkt.getDestinationMAC());

        setUpConnectivity(context, srcId, dstId);*/

//////////////////////////
       //
        
        //forwardPacket(macMetrics);
        //
        // If packetOutOfppTable
        //  Send packet back to the OpenFlow pipeline to match installed flow
        // Else
        //  Send packet direction on the appropriate port
        //
        if (packetOutOfppTable) {
            packetOut(context, PortNumber.TABLE, macMetrics);
        } else {
            packetOut(context, portNumber, macMetrics);
        }
    }


    // Install a rule forwarding the packet to the specified port.
    private void setUpConnectivity(PacketContext context, HostId srcId, HostId dstId) {
        TrafficSelector selector = DefaultTrafficSelector.emptySelector();
        TrafficTreatment treatment = DefaultTrafficTreatment.emptyTreatment();

        Key key;
        if (srcId.toString().compareTo(dstId.toString()) < 0) {
            key = Key.of(srcId.toString() + dstId.toString(), appId);
        } else {
            key = Key.of(dstId.toString() + srcId.toString(), appId);
        }

        HostToHostIntent intent = (HostToHostIntent) intentService.getIntent(key);
        // TODO handle the FAILED state
        if (intent != null) {
            if (WITHDRAWN_STATES.contains(intentService.getIntentState(key))) {
                HostToHostIntent hostIntent = HostToHostIntent.builder()
                        .appId(appId)
                        .key(key)
                        .one(srcId)
                        .two(dstId)
                        .selector(selector)
                        .treatment(treatment)
                        .build();

                intentService.submit(hostIntent);
            } else if (intentService.getIntentState(key) == IntentState.FAILED) {

                TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                        .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                        .drop().build();

                ForwardingObjective objective = DefaultForwardingObjective.builder()
                        .withSelector(objectiveSelector)
                        .withTreatment(dropTreatment)
                        .fromApp(appId)
                        .withPriority(intent.priority() - 1)
                        .makeTemporary(DROP_RULE_TIMEOUT)
                        .withFlag(ForwardingObjective.Flag.VERSATILE)
                        .add();

                flowObjectiveService.forward(context.outPacket().sendThrough(), objective);
            }

        } else if (intent == null) {
            final Constraint constraintBandwidth =
                new BandwidthConstraint(Bandwidth.mbps(0));
            final Constraint constraintLatency =
                new LatencyConstraint(Duration.of(0, ChronoUnit.MICROS));
            final List<Constraint> constraints = new LinkedList<>();

            constraints.add(constraintBandwidth);
            constraints.add(constraintLatency);

            HostToHostIntent hostIntent = HostToHostIntent.builder()
                    .appId(appId)
                    .key(key)
                    .one(srcId)
                    .two(dstId)
                    .selector(selector)
                    .treatment(treatment)
                    .constraints(constraints)
                    .build();

            intentService.submit(hostIntent);
        }

    }

    private class InternalTopologyListener implements TopologyListener {
        @Override
        public void event(TopologyEvent event) {
            List<Event> reasons = event.reasons();
            if (reasons != null) {
                reasons.forEach(re -> {
                    if (re instanceof LinkEvent) {
                        LinkEvent le = (LinkEvent) re;
                        if (le.type() == LinkEvent.Type.LINK_REMOVED && blackHoleExecutor != null) {
                            blackHoleExecutor.submit(() -> fixBlackhole(le.subject().src()));
                        }
                    }
                });
            }
        }
    }

    private void fixBlackhole(ConnectPoint egress) {
        Set<FlowEntry> rules = getFlowRulesFrom(egress);
        Set<SrcDstPair> pairs = findSrcDstPairs(rules);

        Map<DeviceId, Set<Path>> srcPaths = new HashMap<>();

        for (SrcDstPair sd : pairs) {
            // get the edge deviceID for the src host
            Host srcHost = hostService.getHost(HostId.hostId(sd.src));
            Host dstHost = hostService.getHost(HostId.hostId(sd.dst));
            if (srcHost != null && dstHost != null) {
                DeviceId srcId = srcHost.location().deviceId();
                DeviceId dstId = dstHost.location().deviceId();
                log.trace("SRC ID is {}, DST ID is {}", srcId, dstId);

                cleanFlowRules(sd, egress.deviceId());

                Set<Path> shortestPaths = srcPaths.get(srcId);
                if (shortestPaths == null) {
                    shortestPaths = topologyService.getPaths(topologyService.currentTopology(),
                            egress.deviceId(), srcId);
                    srcPaths.put(srcId, shortestPaths);
                }
                backTrackBadNodes(shortestPaths, dstId, sd);
            }
        }
    }

    // Backtracks from link down event to remove flows that lead to blackhole
    private void backTrackBadNodes(Set<Path> shortestPaths, DeviceId dstId, SrcDstPair sd) {
        for (Path p : shortestPaths) {
            List<Link> pathLinks = p.links();
            for (int i = 0; i < pathLinks.size(); i = i + 1) {
                Link curLink = pathLinks.get(i);
                DeviceId curDevice = curLink.src().deviceId();

                // skipping the first link because this link's src has already been pruned beforehand
                if (i != 0) {
                    cleanFlowRules(sd, curDevice);
                }

                Set<Path> pathsFromCurDevice =
                        topologyService.getPaths(topologyService.currentTopology(),
                                                 curDevice, dstId);
                if (pickForwardPathIfPossible(pathsFromCurDevice, curLink.src().port()) != null) {
                    break;
                } else {
                    if (i + 1 == pathLinks.size()) {
                        cleanFlowRules(sd, curLink.dst().deviceId());
                    }
                }
            }
        }
    }

    // Removes flow rules off specified device with specific SrcDstPair
    private void cleanFlowRules(SrcDstPair pair, DeviceId id) {
        log.trace("Searching for flow rules to remove from: {}", id);
        log.trace("Removing flows w/ SRC={}, DST={}", pair.src, pair.dst);
        for (FlowEntry r : flowRuleService.getFlowEntries(id)) {
            boolean matchesSrc = false, matchesDst = false;
            for (Instruction i : r.treatment().allInstructions()) {
                if (i.type() == Instruction.Type.OUTPUT) {
                    // if the flow has matching src and dst
                    for (Criterion cr : r.selector().criteria()) {
                        if (cr.type() == Criterion.Type.ETH_DST) {
                            if (((EthCriterion) cr).mac().equals(pair.dst)) {
                                matchesDst = true;
                            }
                        } else if (cr.type() == Criterion.Type.ETH_SRC) {
                            if (((EthCriterion) cr).mac().equals(pair.src)) {
                                matchesSrc = true;
                            }
                        }
                    }
                }
            }
            if (matchesDst && matchesSrc) {
                log.trace("Removed flow rule from device: {}", id);
                flowRuleService.removeFlowRules((FlowRule) r);
            }
        }

    }

    // Returns a set of src/dst MAC pairs extracted from the specified set of flow entries
    private Set<SrcDstPair> findSrcDstPairs(Set<FlowEntry> rules) {
        ImmutableSet.Builder<SrcDstPair> builder = ImmutableSet.builder();
        for (FlowEntry r : rules) {
            MacAddress src = null, dst = null;
            for (Criterion cr : r.selector().criteria()) {
                if (cr.type() == Criterion.Type.ETH_DST) {
                    dst = ((EthCriterion) cr).mac();
                } else if (cr.type() == Criterion.Type.ETH_SRC) {
                    src = ((EthCriterion) cr).mac();
                }
            }
            builder.add(new SrcDstPair(src, dst));
        }
        return builder.build();
    }

    private ReactiveForwardMetrics createCounter(MacAddress macAddress) {
        ReactiveForwardMetrics macMetrics = null;
        if (recordMetrics) {
            macMetrics = metrics.compute(macAddress, (key, existingValue) -> {
                if (existingValue == null) {
                    return new ReactiveForwardMetrics(0L, 0L, 0L, 0L, macAddress);
                } else {
                    return existingValue;
                }
            });
        }
        return macMetrics;
    }

    private void  forwardPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incrementForwardedPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    private void inPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incrementInPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    private void replyPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incremnetReplyPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    private void droppedPacket(ReactiveForwardMetrics macmetrics) {
        if (recordMetrics) {
            macmetrics.incrementDroppedPacket();
            metrics.put(macmetrics.getMacAddress(), macmetrics);
        }
    }

    public EventuallyConsistentMap<MacAddress, ReactiveForwardMetrics> getMacAddress() {
        return metrics;
    }

    public void printMetric(MacAddress mac) {
        System.out.println("-----------------------------------------------------------------------------------------");
        System.out.println(" MACADDRESS \t\t\t\t\t\t Metrics");
        if (mac != null) {
            System.out.println(" " + mac + " \t\t\t " + metrics.get(mac));
        } else {
            for (MacAddress key : metrics.keySet()) {
                System.out.println(" " + key + " \t\t\t " + metrics.get(key));
            }
        }
    }

    private Set<FlowEntry> getFlowRulesFrom(ConnectPoint egress) {
        ImmutableSet.Builder<FlowEntry> builder = ImmutableSet.builder();
        flowRuleService.getFlowEntries(egress.deviceId()).forEach(r -> {
            if (r.appId() == appId.id()) {
                r.treatment().allInstructions().forEach(i -> {
                    if (i.type() == Instruction.Type.OUTPUT) {
                        if (((Instructions.OutputInstruction) i).port().equals(egress.port())) {
                            builder.add(r);
                        }
                    }
                });
            }
        });

        return builder.build();
    }

    // Wrapper class for a source and destination pair of MAC addresses
    private final class SrcDstPair {
        final MacAddress src;
        final MacAddress dst;

        private SrcDstPair(MacAddress src, MacAddress dst) {
            this.src = src;
            this.dst = dst;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            SrcDstPair that = (SrcDstPair) o;
            return Objects.equals(src, that.src) &&
                    Objects.equals(dst, that.dst);
        }

        @Override
        public int hashCode() {
            return Objects.hash(src, dst);
        }
    }



/// added intents






}