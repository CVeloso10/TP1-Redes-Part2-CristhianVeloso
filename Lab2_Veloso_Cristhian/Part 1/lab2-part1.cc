/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013 ResiliNets, ITTC, University of Kansas
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// C++ Standard Library
#include <iostream>
#include <fstream>
#include <string>
#include <map>

// ns-3 Modules
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/error-model.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"
#include "ns3/enum.h"
#include "ns3/event-id.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Lab2Part1");

// --- Bloco de Rastreamento de Variaveis TCP (Baseado em tcp-variants-comparison.cc) ---

static std::map<uint32_t, bool> firstCwnd;
static std::map<uint32_t, bool> firstSshThr;
static std::map<uint32_t, bool> firstRtt;
static std::map<uint32_t, bool> firstRto;
static std::map<uint32_t, bool> firstNextRx;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> cWndStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> ssThreshStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rttStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rtoStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextTxStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextRxStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> inFlightStream;
static std::map<uint32_t, uint32_t> cWndValue;
static std::map<uint32_t, uint32_t> ssThreshValue;

static uint32_t
GetNodeIdFromContext (std::string context)
{
  std::size_t const n1 = context.find_first_of ("/", 1);
  std::size_t const n2 = context.find_first_of ("/", n1 + 1);
  return std::stoul (context.substr (n1 + 1, n2 - n1 - 1));
}

static void
CwndTracer (std::string context,  uint32_t oldval, uint32_t newval)
{
  uint32_t nodeId = GetNodeIdFromContext (context);

  if (firstCwnd[nodeId])
    {
      *cWndStream[nodeId]->GetStream () << "0.0 " << oldval << std::endl;
      firstCwnd[nodeId] = false;
    }
  *cWndStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  cWndValue[nodeId] = newval;

  if (!firstSshThr[nodeId])
    {
      *ssThreshStream[nodeId]->GetStream ()
          << Simulator::Now ().GetSeconds () << " " << ssThreshValue[nodeId] << std::endl;
    }
}

static void
SsThreshTracer (std::string context, uint32_t oldval, uint32_t newval)
{
  uint32_t nodeId = GetNodeIdFromContext (context);

  if (firstSshThr[nodeId])
    {
      *ssThreshStream[nodeId]->GetStream () << "0.0 " << oldval << std::endl;
      firstSshThr[nodeId] = false;
    }
  *ssThreshStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << newval << std::endl;
  ssThreshValue[nodeId] = newval;

  if (!firstCwnd[nodeId])
    {
      *cWndStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << cWndValue[nodeId] << std::endl;
    }
}

static void
RttTracer (std::string context, Time oldval, Time newval)
{
  uint32_t nodeId = GetNodeIdFromContext (context);

  if (firstRtt[nodeId])
    {
      *rttStream[nodeId]->GetStream () << "0.0 " << oldval.GetSeconds () << std::endl;
      firstRtt[nodeId] = false;
    }
  *rttStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << newval.GetSeconds () << std::endl;
}

static void
RtoTracer (std::string context, Time oldval, Time newval)
{
  uint32_t nodeId = GetNodeIdFromContext (context);

  if (firstRto[nodeId])
    {
      *rtoStream[nodeId]->GetStream () << "0.0 " << oldval.GetSeconds () << std::endl;
      firstRto[nodeId] = false;
    }
  *rtoStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << newval.GetSeconds () << std::endl;
}

static void
NextTxTracer (std::string context, [[maybe_unused]] SequenceNumber32 old, SequenceNumber32 nextTx)
{
  uint32_t nodeId = GetNodeIdFromContext (context);
  *nextTxStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << nextTx << std::endl;
}

static void
InFlightTracer (std::string context, [[maybe_unused]] uint32_t old, uint32_t inFlight)
{
  uint32_t nodeId = GetNodeIdFromContext (context);
  *inFlightStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << inFlight << std::endl;
}

static void
NextRxTracer (std::string context, [[maybe_unused]] SequenceNumber32 old, SequenceNumber32 nextRx)
{
  uint32_t nodeId = GetNodeIdFromContext (context);
    if (firstNextRx[nodeId])
    {
      *nextRxStream[nodeId]->GetStream () << "0.0 " << old << std::endl;
      firstNextRx[nodeId] = false;
    }
  *nextRxStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << nextRx << std::endl;
}

static void
TraceCwnd (std::string cwnd_tr_file_name, uint32_t nodeId, uint32_t socketId, uint32_t mapKey)
{
  AsciiTraceHelper ascii;
  cWndStream[mapKey] = ascii.CreateFileStream (cwnd_tr_file_name.c_str ());
  Config::Connect ("/NodeList/" + std::to_string (nodeId) + "/$ns3::TcpL4Protocol/SocketList/" + std::to_string (socketId) + "/CongestionWindow",
                   MakeCallback (&CwndTracer));
}

static void
TraceSsThresh (std::string ssthresh_tr_file_name, uint32_t nodeId, uint32_t socketId, uint32_t mapKey)
{
  AsciiTraceHelper ascii;
  ssThreshStream[mapKey] = ascii.CreateFileStream (ssthresh_tr_file_name.c_str ());
  Config::Connect ("/NodeList/" + std::to_string (nodeId) + "/$ns3::TcpL4Protocol/SocketList/" + std::to_string (socketId) + "/SlowStartThreshold",
                   MakeCallback (&SsThreshTracer));
}

static void
TraceRtt (std::string rtt_tr_file_name, uint32_t nodeId, uint32_t socketId, uint32_t mapKey)
{
  AsciiTraceHelper ascii;
  rttStream[mapKey] = ascii.CreateFileStream (rtt_tr_file_name.c_str ());
  Config::Connect ("/NodeList/" + std::to_string (nodeId) + "/$ns3::TcpL4Protocol/SocketList/" + std::to_string (socketId) + "/RTT",
                   MakeCallback (&RttTracer));
}

static void
TraceRto (std::string rto_tr_file_name, uint32_t nodeId, uint32_t socketId, uint32_t mapKey)
{
  AsciiTraceHelper ascii;
  rtoStream[mapKey] = ascii.CreateFileStream (rto_tr_file_name.c_str ());
  Config::Connect ("/NodeList/" + std::to_string (nodeId) + "/$ns3::TcpL4Protocol/SocketList/" + std::to_string (socketId) + "/RTO",
                   MakeCallback (&RtoTracer));
}

static void
TraceNextTx (std::string &next_tx_seq_file_name, uint32_t nodeId, uint32_t socketId, uint32_t mapKey)
{
  AsciiTraceHelper ascii;
  nextTxStream[mapKey] = ascii.CreateFileStream (next_tx_seq_file_name.c_str ());
  Config::Connect ("/NodeList/" + std::to_string (nodeId) + "/$ns3::TcpL4Protocol/SocketList/" + std::to_string (socketId) + "/NextTxSequence",
                   MakeCallback (&NextTxTracer));
}

static void
TraceInFlight (std::string &in_flight_file_name, uint32_t nodeId, uint32_t socketId, uint32_t mapKey)
{
  AsciiTraceHelper ascii;
  inFlightStream[mapKey] = ascii.CreateFileStream (in_flight_file_name.c_str ());
  Config::Connect ("/NodeList/" + std::to_string (nodeId) + "/$ns3::TcpL4Protocol/SocketList/" + std::to_string (socketId) + "/BytesInFlight",
                   MakeCallback (&InFlightTracer));
}

static void
TraceNextRx (std::string &next_rx_seq_file_name, uint32_t nodeId, uint32_t socketId, uint32_t mapKey)
{
  AsciiTraceHelper ascii;
  nextRxStream[mapKey] = ascii.CreateFileStream (next_rx_seq_file_name.c_str ());
  Config::Connect ("/NodeList/" + std::to_string (nodeId) +
                       "/$ns3::TcpL4Protocol/SocketList/" + std::to_string (socketId) + "/RxBuffer/NextRxSequence",
                   MakeCallback (&NextRxTracer));
}

// --- Fim do Bloco de Rastreamento ---

int main (int argc, char *argv[])
{
  // Parâmetros de Linha de Comando
  std::string transport_prot = "TcpCubic";
  std::string dataRate = "1Mbps";
  std::string delay = "20ms";
  double errorRate = 0.00001;
  uint16_t num_flows = 1;
  bool tracing = false;
  std::string prefix_file_name = "lab2-part1";
  bool flow_monitor = false;

  CommandLine cmd (__FILE__);
  cmd.AddValue ("transport_prot", "Transport protocol to use: TcpCubic or TcpNewReno", transport_prot);
  cmd.AddValue ("dataRate", "Bottleneck data rate", dataRate);
  cmd.AddValue ("delay", "Bottleneck delay", delay);
  cmd.AddValue ("errorRate", "Bottleneck error rate", errorRate);
  cmd.AddValue ("nFlows", "Number of flows (max 20)", num_flows);
  cmd.AddValue ("tracing", "Flag to enable/disable tracing", tracing);
  cmd.AddValue ("prefix_name", "Prefix of output trace file", prefix_file_name);
  cmd.AddValue ("flow_monitor", "Enable flow monitor", flow_monitor);
  cmd.Parse (argc, argv);

  // Validação dos parâmetros
  if (num_flows > 20)
    {
      std::cout << "Error: nFlows cannot exceed 20." << std::endl;
      return 1;
    }
  
  if (transport_prot != "TcpCubic" && transport_prot != "TcpNewReno")
    {
      std::cout << "Error: transport_prot must be TcpCubic or TcpNewReno." << std::endl;
      return 1;
    }

  transport_prot = std::string ("ns3::") + transport_prot;

  SeedManager::SetSeed (1);

  // Configuração do tipo de socket TCP
  // (As linhas de RcvBufSize, SndBufSize, Sack, e RecoveryType foram removidas 
  // conforme o roteiro [cite: 5110-5112])
  if (transport_prot.compare ("ns3::TcpWestwoodPlus") == 0)
    { 
      Config::SetDefault ("ns3::TcpL4Protocol::SocketType", TypeIdValue (TcpWestwood::GetTypeId ()));
      Config::SetDefault ("ns3::TcpWestwood::ProtocolType", EnumValue (TcpWestwood::WESTWOODPLUS));
    }
  else
    {
      TypeId tcpTid;
      NS_ABORT_MSG_UNLESS (TypeId::LookupByNameFailSafe (transport_prot, &tcpTid), "TypeId " << transport_prot << " not found");
      Config::SetDefault ("ns3::TcpL4Protocol::SocketType", TypeIdValue (TypeId::LookupByName (transport_prot)));
    }
  
  // Tempos de Simulação
  double start_time = 1.0; 
  double stop_time = 20.0;

  // Topologia: [n0] --p2p-- [n1] --p2p_gargalo-- [n2] --p2p-- [n3]
  NS_LOG_INFO ("Criando topologia...");
  NodeContainer nodes;
  nodes.Create (4);
  NodeContainer n0n1 = NodeContainer (nodes.Get (0), nodes.Get (1)); // source -> r1
  NodeContainer n1n2 = NodeContainer (nodes.Get (1), nodes.Get (2)); // r1 -> r2 (gargalo)
  NodeContainer n2n3 = NodeContainer (nodes.Get (2), nodes.Get (3)); // r2 -> dest

  // Modelo de Erro (baseado em fifth.cc [cite: 5113-5114])
  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
  em->SetAttribute ("ErrorRate", DoubleValue (errorRate));

  // Configuração dos Links
  PointToPointHelper p2pAccess;
  p2pAccess.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  p2pAccess.SetChannelAttribute ("Delay", StringValue ("0.01ms"));
  
  PointToPointHelper p2pBottleneck;
  p2pBottleneck.SetDeviceAttribute ("DataRate", StringValue (dataRate));
  p2pBottleneck.SetChannelAttribute ("Delay", StringValue (delay));
  p2pBottleneck.SetDeviceAttribute ("ReceiveErrorModel", PointerValue (em));

  NetDeviceContainer d0d1 = p2pAccess.Install (n0n1);
  NetDeviceContainer d1d2 = p2pBottleneck.Install (n1n2);
  NetDeviceContainer d2d3 = p2pAccess.Install (n2n3); 

  // Instalação da Pilha de Internet
  InternetStackHelper stack;
  stack.Install (nodes);

  // Atribuição de Endereços IP
  Ipv4AddressHelper address;
  Ipv4InterfaceContainer i2i3; 

  address.SetBase ("10.1.1.0", "255.255.255.0");
  address.Assign (d0d1);

  address.SetBase ("10.1.2.0", "255.255.255.0");
  address.Assign (d1d2);

  address.SetBase ("10.1.3.0", "255.255.255.0");
  i2i3 = address.Assign (d2d3); // Guarda as interfaces do último link

  // Roteamento Global
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // Configuração das Aplicações
  uint16_t port = 50000;
  ApplicationContainer sinkApps;

  // Instala Sinks no nó de destino (nodes.Get(3))
  for (uint32_t i = 0; i < num_flows; ++i)
    {
      Address sinkAddress (InetSocketAddress (Ipv4Address::GetAny (), port + i));
      PacketSinkHelper pktSinkHelper ("ns3::TcpSocketFactory", sinkAddress);
      ApplicationContainer apps = pktSinkHelper.Install (nodes.Get (3));
      sinkApps.Add (apps);
    }
  sinkApps.Start (Seconds (0.0));
  sinkApps.Stop (Seconds (stop_time));

  ApplicationContainer sourceApps;
  // Instala Sources no nó de origem (nodes.Get(0))
  for (uint32_t i = 0; i < num_flows; ++i)
    {
      AddressValue remoteAddress (InetSocketAddress (i2i3.GetAddress (1), port + i));
      
      BulkSendHelper ftp ("ns3::TcpSocketFactory", Address ());
      ftp.SetAttribute ("Remote", remoteAddress);
      ftp.SetAttribute ("MaxBytes", UintegerValue (0)); // 0 = Envio ilimitado [cite: 5129]

      ApplicationContainer apps = ftp.Install (nodes.Get (0));
      sourceApps.Add (apps);
    }
  sourceApps.Start (Seconds (start_time));
  sourceApps.Stop (Seconds (stop_time));

  // Configuração de Rastreamento (CWND, etc.)
  if (tracing)
    {
      AsciiTraceHelper ascii;
      
      uint32_t sourceMapKey = 0;
      uint32_t sinkMapKey = 3; 

      firstCwnd[sourceMapKey] = true;
      firstSshThr[sourceMapKey] = true;
      firstRtt[sourceMapKey] = true;
      firstRto[sourceMapKey] = true;
      firstNextRx[sinkMapKey] = true;

      std::string flowString = "";
      if (num_flows > 1)
        {
          NS_LOG_WARN ("Rastreamento de CWND habilitado, mas nFlows > 1. "
                       "Apenas o fluxo 0 (Socket 0) será rastreado.");
          flowString = "-flow0";
        }

      Simulator::Schedule (Seconds (start_time + 0.00001), &TraceCwnd,
                           prefix_file_name + flowString + "-cwnd.data", 0, 0, sourceMapKey);
      Simulator::Schedule (Seconds (start_time + 0.00001), &TraceSsThresh,
                           prefix_file_name + flowString + "-ssth.data", 0, 0, sourceMapKey);
      Simulator::Schedule (Seconds (start_time + 0.00001), &TraceRtt,
                           prefix_file_name + flowString + "-rtt.data", 0, 0, sourceMapKey);
      Simulator::Schedule (Seconds (start_time + 0.00001), &TraceRto,
                           prefix_file_name + flowString + "-rto.data", 0, 0, sourceMapKey);
      Simulator::Schedule (Seconds (start_time + 0.00001), &TraceNextTx,
                           prefix_file_name + flowString + "-next-tx.data", 0, 0, sourceMapKey);
      Simulator::Schedule (Seconds (start_time + 0.00001), &TraceInFlight,
                           prefix_file_name + flowString + "-inflight.data", 0, 0, sourceMapKey);
      
      Simulator::Schedule (Seconds (start_time + 0.1), &TraceNextRx,
                           prefix_file_name + flowString + "-next-rx.data", 3, 0, sinkMapKey);
    }

  // Flow Monitor
  FlowMonitorHelper flowHelper;
  Ptr<FlowMonitor> monitor;
  if (flow_monitor)
    {
      monitor = flowHelper.InstallAll ();
    }

  // Execução
  Simulator::Stop (Seconds (stop_time));
  Simulator::Run ();

  // Processamento de Saída (Goodput)
  if (flow_monitor)
    {
      monitor->CheckForLostPackets ();
      flowHelper.SerializeToXmlFile (prefix_file_name + ".flowmonitor", true, true);

      std::cout << std::endl;
      std::cout << "--- Resultados do Goodput (Flow Monitor) ---" << std::endl;
      
      Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier ());
      FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();
      
      double duration = stop_time - start_time;
      double aggregateGoodputBps = 0.0;
      
      for (auto const& [flowId, flowStats] : stats)
        {
          Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (flowId);

          // Filtra apenas fluxos de dados para dest (10.1.3.2), ignora ACKs
          if (t.destinationAddress == "10.1.3.2")
            {
              double goodput_bps = (flowStats.rxBytes * 8.0) / duration;
              double goodput_kbps = goodput_bps / 1000.0;

              aggregateGoodputBps += goodput_bps;

              std::cout << "  Fluxo " << flowId << " (" << t.sourceAddress << ":" << t.sourcePort 
                        << " -> " << t.destinationAddress << ":" << t.destinationPort << ")" << std::endl;
              std::cout << "    Goodput (individual): " << goodput_bps << " bps (" 
                        << goodput_kbps << " kbps)" << std::endl;
              std::cout << "    Rx Bytes:             " << flowStats.rxBytes << std::endl;
            }
        }
      
      std::cout << "------------------------------------------" << std::endl;
      // Linha de resumo para scripts de automação
      std::cout << "Goodput Agregado (soma): " << aggregateGoodputBps << " bps" << std::endl;
      std::cout << "------------------------------------------" << std::endl;

    }

  Simulator::Destroy ();
  return 0;
}
