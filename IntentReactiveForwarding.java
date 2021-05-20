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
package mx.itesm.ibfwd;

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
import org.onosproject.net.PortNumber;


//traffic engineering
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;

//trafficengineering GET web
import javax.ws.rs.*;
import javax.ws.rs.Path;
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


import java.util.EnumSet;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * WORK-IN-PROGRESS: Sample reactive forwarding application using intent framework.
 */
@Component(immediate = true)
public class IntentReactiveForwarding {

    private final Logger log = getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected HostService hostService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowObjectiveService flowObjectiveService;





    private ReactivePacketProcessor processor = new ReactivePacketProcessor();
    private ApplicationId appId;

    private static final int DROP_RULE_TIMEOUT = 60;

    private static final EnumSet<IntentState> WITHDRAWN_STATES = EnumSet.of(IntentState.WITHDRAWN,
                                                                            IntentState.WITHDRAWING,
                                                                            IntentState.WITHDRAW_REQ);

    //hashmap to store important info about possible malicious
    private static HashMap<String, List<String>> hashPossibleMalicious;
    private static List<String> values;
    private static int vecesEntro = 0;
    //get bandwidth value
    // private static BasicLinkConfig basicLinkConfig;
    // private static LinkKey getLinkKey;
    // private static ConnectPoint connectionPointSRC, connectionPointDST;
    // private static ElementId elementId;

    @Activate
    public void activate() {
        appId = coreService.registerApplication("org.onosproject.ibfwd");

        packetService.addProcessor(processor, PacketProcessor.director(2));

        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
        //log.info("elementid "+elementId.toString());
        log.info("Startedsssssssssss");
        
    }

    @Deactivate
    public void deactivate() {
        packetService.removeProcessor(processor);
        processor = null;
        log.info("Stopped");
    }




    /**
     * Packet processor responsible for forwarding packets along their paths.
     */

    /**
     * REST API for bandwidth monitoring and path rerouting among network.
     */
    @Path("")
    private class ReactivePacketProcessor  extends AbstractWebResource implements PacketProcessor{
        private final Logger log = LoggerFactory.getLogger(getClass());
         

    @GET
    @Path("/test")
    public Response getTest() {
        ObjectNode responseBody = new ObjectNode(JsonNodeFactory.instance);
        responseBody.put("message", "it works!");
        return Response.status(200).entity(responseBody).build();
    }

    /**
     * Get bandwidth from all links and edges.
     *
     * @return 200 OK
     */
    @GET
    @Path("bandwidth/topology")
    @Produces(MediaType.APPLICATION_JSON)
    public ObjectNode getTopologyBandwidth() {

        LinkService linkService = get(LinkService.class);
        HostService hostService = get(HostService.class);
        PortStatisticsService portStatisticsService = get(PortStatisticsService.class);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();

        ArrayNode linksNode = mapper.createArrayNode();
        for (Link link: linkService.getActiveLinks()){

            long srcBw = portStatisticsService.load(link.src()).rate() * 8 / 1000;
            long dstBw = portStatisticsService.load(link.dst()).rate() * 8 / 1000;

            // unit: Kbps
            ObjectNode linkNode = mapper.createObjectNode()
                    .put("src", link.src().deviceId().toString())
                    .put("dst", link.dst().deviceId().toString())
                    .put("bw", (srcBw + dstBw) / 2 );

            linksNode.add(linkNode);
        }

        rootNode.set("links", linksNode);

        ArrayNode edgesNode = mapper.createArrayNode();
        for (Host host: hostService.getHosts()){
            // unit: Kbps
            ObjectNode hostNode = mapper.createObjectNode()
                    .put("host", host.id().toString())
                    .put("location", host.location().deviceId().toString())
                    .put("bw", portStatisticsService.load(host.location()).rate() * 8 / 1000);

            edgesNode.add(hostNode);
        }

        rootNode.set("edges", edgesNode);
        //log.info("Roooteeeeeeeeeeee Node\n {}",rootNode);

        //log.info("result {}",getTopologyBandwidth());

        return rootNode;

    }



         /**
         * Processes the provided TCP packet
         * @param context packet context
         * @param eth ethernet packet
         */
        @Override
        public void process(PacketContext context) {

            // Stop processing if the packet has been handled, since we
            // can't do any more to it.
            if (context.isHandled()) {
                return;
            }
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            HostId srcId = HostId.hostId(ethPkt.getSourceMAC());
            HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());

            // Do we know who this is for? If not, flood and bail.
            Host dst = hostService.getHost(dstId);
            if (dst == null) {
                flood(context);
                return;
            }
            //obtiene los links, el 1, y el src
            //log.info("getTopoBand {}",getTopologyBandwidth().get("links").get(1).get("src"));
            //log.info("getTopoBand {}",getTopologyBandwidth().get("links"));
            log.info("getTopoBand {}",getTopologyBandwidth().getClass());
            
            
            //log.info("\n size links {}",getTopologyBandwidth().getHosts() );

       
  

            // Otherwise forward and be done with it.
            setUpConnectivity(context, srcId, dstId);
            forwardPacketToDst(context, dst);

            Ethernet packeteth = context.inPacket().parsed();

            DeviceId deviceId = context.inPacket().receivedFrom().deviceId();
            IPv4 ipv4 = (IPv4) packeteth.getPayload();
            int srcip = ipv4.getSourceAddress();
            String srcips = Ip4Address.valueOf(srcip).toString();//added
            int dstip = ipv4.getDestinationAddress();
            String dstips = Ip4Address.valueOf(dstip).toString(); //added
            byte proto = ipv4.getProtocol();
            int srcport = 0;
            int dstport = 0;
            
            String protocolS = "TCP";

            if (proto==6) {
                TCP tcp = (TCP) ipv4.getPayload();
                srcport = tcp.getSourcePort();
                dstport = tcp.getDestinationPort();
            } else {
                UDP udp = (UDP) ipv4.getPayload();
                srcport = udp.getSourcePort();
                dstport = udp.getDestinationPort();
                protocolS = "UDP";
            }


           //log.info("SRC MAC: "+ethPkt.getSourceMAC()+" DSTMAC: "+ethPkt.getDestinationMAC());
            //System.out.println("srcip: "+srcip+" srcport: "+srcport);
            //atacante h4, victima h1
            //log.info("The attacker is "+ethPkt.getSourceMAC().toString());
            //log.info("2 hash "+vecesEntro);


            //AGREGAR TAMBIEN UN TIMEMILISECONDS PARA SACAR DEL HASH CADA CIERT TIEMPO LOS FLUJOS MALIGNOS Y NO SE QUEDEN EN MEMORIA
            hashPossibleMalicious = new HashMap<String, List<String>>();
            values = new ArrayList<String>();
            
            //Si el flujo es atacante, y no esta en el hash
            //Redirigir a los canales menos usados en terminos de bandwidth, instalar reglas HARDTIMEOUT e IDLE
            if(ethPkt.getSourceMAC().toString().equals("00:00:00:00:00:04") && 
                ethPkt.getDestinationMAC().toString().equals("00:00:00:00:00:01") &&
                hashPossibleMalicious.containsKey(srcips) == false ){
                log.info("The attacker is "+ethPkt.getSourceMAC().toString());

                //Agregar a hashmap, para que la 2da vez que pase sea mitigado
                vecesEntro = vecesEntro + 1;
                //log.info("vecesEntro "+vecesEntro);
                //ipdestino
                values.add(dstips);
                //mac origen
                values.add(ethPkt.getSourceMAC().toString());
                //mac destino
                values.add(ethPkt.getDestinationMAC().toString());
                //puerto origen
                values.add(""+srcport);
                //puerto destino
                values.add(""+dstport);
                //colocar 1 vez agregado
                values.add("First time added");
                //la llave es la ip origen    
                hashPossibleMalicious.put(srcips, values);
                log.info("SIZE "+hashPossibleMalicious.size());
                int i = 0;
                // to get the arraylist values of the given hashmap key
                for( String value : values) {
                    //System.out.println(""+i+" "+hm.get(srcips).get(i));
                    log.info(""+i+" "+hashPossibleMalicious.get(srcips).get(i));
                    i++;
                }

                //AGREGAR PARTE DE CODIGO DE REDIRIGIR ESTE FLUJO MALIGNO A LOS CANALES MENOS USADOS

               // Agregar regla de flujo con IDLE TIMEOUT Y HARDTIMEOUT ( esto aun no funciona)
                // FlowRule transitFlowRule = DefaultFlowRule.builder()
                //     .forDevice(this.data().deviceId())
                //     .withSelector(sBuilder.build())
                //     .withTreatment(instTreatment)
                //     .withPriority(125)
                //     .forTable(IntConstants.INGRESS_PROCESS_INT_SOURCE_TB_INT_SOURCE)
                //     .fromApp(appId)
                //     .withIdleTimeout(IDLE_TIMEOUT)
                //     .build();
                //break; 

                
            }
            //Si el atacante ya esta en el hash, entonces mitigar ese flujo, en el switch mas cercano al atacante
            else if(ethPkt.getSourceMAC().toString().equals("00:00:00:00:00:04") && 
                ethPkt.getDestinationMAC().toString().equals("00:00:00:00:00:01") &&
                hashPossibleMalicious.containsKey(srcips) == true ){            

                // cortar trafico (ya funciona)
                // TrafficSelector objectiveSelector = DefaultTrafficSelector.builder()
                //         .matchEthSrc(srcId.mac()).matchEthDst(dstId.mac()).build();

                // TrafficTreatment dropTreatment = DefaultTrafficTreatment.builder()
                //         .drop().build();

                // ForwardingObjective objective = DefaultForwardingObjective.builder()
                //         .withSelector(objectiveSelector)
                //         .withTreatment(dropTreatment)
                //         .fromApp(appId)
                //         .withPriority(150)
                //         .makeTemporary(DROP_RULE_TIMEOUT)
                //         .withFlag(ForwardingObjective.Flag.VERSATILE)
                //         .add();

                // flowObjectiveService.forward(context.outPacket().sendThrough(), objective);

            }    
     

        }
    }

    // Floods the specified packet if permissible.
    private void flood(PacketContext context) {
        if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
                                             context.inPacket().receivedFrom())) {
            packetOut(context, PortNumber.FLOOD);
        } else {
            context.block();
        }
    }

    // Sends a packet out the specified port.
    private void packetOut(PacketContext context, PortNumber portNumber) {
        context.treatmentBuilder().setOutput(portNumber);
        context.send();
    }

    private void forwardPacketToDst(PacketContext context, Host dst) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(dst.location().port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(dst.location().deviceId(),
                                                          treatment, context.inPacket().unparsed());
        packetService.emit(packet);
        //log.info("sending packet: {}", packet);

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

        } else if (intent == null ) {
            HostToHostIntent hostIntent = HostToHostIntent.builder()
                    .appId(appId)
                    .key(key)
                    .one(srcId)
                    .two(dstId)
                    .selector(selector)
                    .treatment(treatment)
                    .build();

            intentService.submit(hostIntent);
        }

    }


 
}

