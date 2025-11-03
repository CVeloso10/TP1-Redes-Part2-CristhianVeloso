/*
 * Este é o script para o Lab 2, Parte 1.
 * Baseado em examples/tcp/tcp-variants-comparison.cc e modificado
 * conforme o roteiro de ECE 6110 Lab 2 (Lab2.pdf).
 */

#include <iostream>
#include <fstream>
#include <string>
#include <map>

#include "ns3/flow-monitor-module.h"
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
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Lab2Part1");

// --- Início do Bloco de Rastreamento (de tcp-variants-comparison.cc) ---
// Estas funções e mapas globais são usados para rastrear as variáveis do TCP
// para a Parte 1a (plot da janela de congestão).

static std::map<uint32_t, bool> firstCwnd;
static std::map<uint32_t, bool> firstSshThr;
static std::map<uint32_t, bool> firstRtt;
static std::map<uint32_t, bool> firstRto;
static std::map<uint32_t, bool> firstNextRx; // Adicionado para rastrear NextRx
static std::map<uint32_t, Ptr<OutputStreamWrapper>> cWndStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> ssThreshStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rttStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> rtoStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextTxStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> nextRxStream;
static std::map<uint32_t, Ptr<OutputStreamWrapper>> inFlightStream;
static std::map<uint32_t, uint32_t> cWndValue;
static std::map<uint32_t, uint32_t> ssThreshValue;

// Função para extrair o Node ID do contexto de rastreamento
static uint32_t
GetNodeIdFromContext (std::string context)
{
  std::size_t const n1 = context.find_first_of ("/", 1);
  std::size_t const n2 = context.find_first_of ("/", n1 + 1);
  return std::stoul (context.substr (n1 + 1, n2 - n1 - 1));
}

// Rastreia mudanças na Janela de Congestão (Cwnd)
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

// Rastreia mudanças no Limite de Slow Start (SsThresh)
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

// Rastreia mudanças no RTT
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

// Rastreia mudanças no RTO
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

// Rastreia o próximo SeqNum de TX
static void
NextTxTracer (std::string context, [[maybe_unused]] SequenceNumber32 old, SequenceNumber32 nextTx)
{
  uint32_t nodeId = GetNodeIdFromContext (context);
  *nextTxStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << nextTx << std::endl;
}

// Rastreia Bytes em Trânsito
static void
InFlightTracer (std::string context, [[maybe_unused]] uint32_t old, uint32_t inFlight)
{
  uint32_t nodeId = GetNodeIdFromContext (context);
  *inFlightStream[nodeId]->GetStream () << Simulator::Now ().GetSeconds () << " " << inFlight << std::endl;
}

// Rastreia o próximo SeqNum de RX
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

// Funções Helper para agendar e conectar os rastreadores
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
  // --- 1. Configuração dos Parâmetros de Linha de Comando ---
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

  // --- 2. Remoções Obrigatórias do Roteiro ---
  // As linhas para RcvBufSize, SndBufSize, Sack, e RecoveryType
  // de tcp-variants-comparison.cc foram removidas[cite: 5999, 6000, 6001].

  // --- 3. Configuração do TCP ---
  // Seleciona a variante TCP
  if (transport_prot.compare ("ns3::TcpWestwoodPlus") == 0)
    { 
      // O código base original tinha isso, manteremos por robustez
      Config::SetDefault ("ns3::TcpL4Protocol::SocketType", TypeIdValue (TcpWestwood::GetTypeId ()));
      Config::SetDefault ("ns3::TcpWestwood::ProtocolType", EnumValue (TcpWestwood::WESTWOODPLUS));
    }
  else
    {
      TypeId tcpTid;
      NS_ABORT_MSG_UNLESS (TypeId::LookupByNameFailSafe (transport_prot, &tcpTid), "TypeId " << transport_prot << " not found");
      Config::SetDefault ("ns3::TcpL4Protocol::SocketType", TypeIdValue (TypeId::LookupByName (transport_prot)));
    }
  
  // --- 4. Configuração dos Tempos de Simulação ---
  double start_time = 1.0;  // Início dos fluxos 
  double stop_time = 20.0; // Fim da simulação 

  // --- 5. Criação da Topologia (4 Nós, 3 Links) ---
  // [source] --100Mbps, 0.01ms-- [r1] --(gargalo)-- [r2] --100Mbps, 0.01ms-- [dest]
  
  NodeContainer nodes;
  nodes.Create (4);
  NodeContainer n0n1 = NodeContainer (nodes.Get (0), nodes.Get (1));
  NodeContainer n1n2 = NodeContainer (nodes.Get (1), nodes.Get (2));
  NodeContainer n2n3 = NodeContainer (nodes.Get (2), nodes.Get (3));

  // --- 6. Configuração do Modelo de Erro (de fifth.cc) ---
  // 
  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
  em->SetAttribute ("ErrorRate", DoubleValue (errorRate));

  // --- 7. Configuração dos Links Ponto-a-Ponto ---
  
  // Link de Acesso (source <-> r1)
  PointToPointHelper p2pAccess;
  p2pAccess.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  p2pAccess.SetChannelAttribute ("Delay", StringValue ("0.01ms"));
  NetDeviceContainer d0d1 = p2pAccess.Install (n0n1);

  // Link de Gargalo (r1 <-> r2)
  PointToPointHelper p2pBottleneck;
  p2pBottleneck.SetDeviceAttribute ("DataRate", StringValue (dataRate));
  p2pBottleneck.SetChannelAttribute ("Delay", StringValue (delay));
  p2pBottleneck.SetDeviceAttribute ("ReceiveErrorModel", PointerValue (em)); // Aplicando o modelo de erro
  NetDeviceContainer d1d2 = p2pBottleneck.Install (n1n2);

  // Link de Acesso (r2 <-> dest)
  NetDeviceContainer d2d3 = p2pAccess.Install (n2n3); // Reutiliza o helper de acesso

  // --- 8. Instalação da Pilha de Internet e Roteamento ---
  InternetStackHelper stack;
  stack.Install (nodes); // Instala em todos os 4 nós

  Ipv4AddressHelper address;
  Ipv4InterfaceContainer i2i3; // Precisamos disso para o endereço de destino

  address.SetBase ("10.1.1.0", "255.255.255.0");
  address.Assign (d0d1);

  address.SetBase ("10.1.2.0", "255.255.255.0");
  address.Assign (d1d2);

  address.SetBase ("10.1.3.0", "255.255.255.0");
  i2i3 = address.Assign (d2d3);

  // Popula as tabelas de roteamento
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // --- 9. Configuração das Aplicações (Sink e Source) ---
  
  uint16_t port = 50000;
  ApplicationContainer sinkApps;

  // Instala nFlows Sinks (receptores) no nó de destino (nodes.Get(3))
  for (uint32_t i = 0; i < num_flows; ++i)
    {
      Address sinkAddress (InetSocketAddress (Ipv4Address::GetAny (), port + i));
      PacketSinkHelper pktSinkHelper ("ns3::TcpSocketFactory", sinkAddress);
      ApplicationContainer apps = pktSinkHelper.Install (nodes.Get (3));
      sinkApps.Add (apps);
    }
  sinkApps.Start (Seconds (0.0)); // 
  sinkApps.Stop (Seconds (stop_time));

  ApplicationContainer sourceApps;
  // Instala nFlows Sources (emissores) no nó de origem (nodes.Get(0))
  for (uint32_t i = 0; i < num_flows; ++i)
    {
      // O destino é a interface 1 do link d2d3 (nó 'dest')
      AddressValue remoteAddress (InetSocketAddress (i2i3.GetAddress (1), port + i));
      
      BulkSendHelper ftp ("ns3::TcpSocketFactory", Address ());
      ftp.SetAttribute ("Remote", remoteAddress);
      ftp.SetAttribute ("MaxBytes", UintegerValue (0)); // 

      ApplicationContainer apps = ftp.Install (nodes.Get (0));
      sourceApps.Add (apps);
    }
  sourceApps.Start (Seconds (start_time)); // 
  sourceApps.Stop (Seconds (stop_time));

  // --- 10. Configuração de Rastreamento (CWND, etc.) ---
  if (tracing)
    {
      AsciiTraceHelper ascii;
      // O roteiro só pede plot de CWND para 1 fluxo[cite: 6024].
      // Este código de rastreamento só funciona corretamente para 1 fluxo
      // (rastreia o socket 0 nos nós de origem e destino).
      
      // Chave do mapa para o nó de origem (ID 0)
      uint32_t sourceMapKey = 0;
      // Chave do mapa para o nó de destino (ID 3)
      uint32_t sinkMapKey = 3; 

      firstCwnd[sourceMapKey] = true;
      firstSshThr[sourceMapKey] = true;
      firstRtt[sourceMapKey] = true;
      firstRto[sourceMapKey] = true;
      firstNextRx[sinkMapKey] = true;

      std::string flowString = "";
      if (num_flows > 1)
        {
          NS_LOG_WARN ("O rastreamento de CWND está habilitado, mas nFlows > 1. "
                       "Apenas o fluxo 0 (Socket 0) será rastreado.");
          flowString = "-flow0";
        }

      // Agendando rastreadores para o nó de origem (ID 0, Socket 0)
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
      
      // Agendando rastreador para o nó de destino (ID 3, Socket 0)
      Simulator::Schedule (Seconds (start_time + 0.1), &TraceNextRx,
                           prefix_file_name + flowString + "-next-rx.data", 3, 0, sinkMapKey);
    }

  // --- 11. Flow Monitor (para Goodput) ---
  FlowMonitorHelper flowHelper;
  Ptr<FlowMonitor> monitor;
  if (flow_monitor)
    {
      monitor = flowHelper.InstallAll ();
    }

  // --- 12. Execução da Simulação ---
  Simulator::Stop (Seconds (stop_time));
  Simulator::Run ();

  // --- 13. Processamento de Saída (Goodput) ---
  if (flow_monitor)
    {
      monitor->CheckForLostPackets ();
      flowHelper.SerializeToXmlFile (prefix_file_name + ".flowmonitor", true, true);

      std::cout << std::endl;
      std::cout << "--- Resultados do Goodput (Flow Monitor) ---" << std::endl;
      
      Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier ());
      FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();
      
      // Duração ativa do fluxo conforme nota de rodapé do Lab2.pdf
      double duration = stop_time - start_time;
      double aggregateGoodputBps = 0.0;
      
      for (auto const& [flowId, flowStats] : stats)
        {
          Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (flowId);

          // --- CORREÇÃO ADICIONADA AQUI ---
          // Filtra apenas os fluxos de dados que chegam ao nó de destino (dest, IP: 10.1.3.2)
          // Isso ignora os fluxos de ACKs que retornam ao cliente.
          if (t.destinationAddress == "10.1.3.2")
            {
              // Goodput = (Total de Bytes Recebidos * 8 bits/byte) / Duração em segundos
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
      // Imprime o valor agregado total que o script run-part1c.sh irá capturar
      // Esta linha é a única que deve conter a palavra "Goodput:" para o script de automação
      std::cout << "Goodput Agregado (soma): " << aggregateGoodputBps << " bps" << std::endl;
      std::cout << "------------------------------------------" << std::endl;

    }

  Simulator::Destroy ();
  return 0;
}