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

#include <iostream>
#include <fstream>
#include <string>
#include <map>

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
#include "ns3/flow-monitor-module.h" 
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/traffic-control-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("Lab2Part2");

int main (int argc, char *argv[])
{
  std::string transport_prot = "TcpCubic";
  std::string dataRate = "1Mbps";
  std::string delay = "20ms";
  double errorRate = 0.00001;
  uint16_t num_flows = 2; // O padrão é 2
  uint32_t run = 0; // Parâmetro para o RNG
  
  bool flow_monitor = false; 

  CommandLine cmd (__FILE__);
  cmd.AddValue ("transport_prot", "Transport protocol to use: TcpCubic or TcpNewReno", transport_prot);
  cmd.AddValue ("dataRate", "Bottleneck data rate (default: 1Mbps)", dataRate);
  cmd.AddValue ("delay", "Bottleneck delay (default: 20ms)", delay);
  cmd.AddValue ("errorRate", "Bottleneck error rate (default: 0.00001)", errorRate);
  cmd.AddValue ("nFlows", "Number of flows (DEVE SER PAR, max 20)", num_flows);
  cmd.AddValue ("run", "Run number for RNG seed", run); 
  cmd.AddValue ("flow_monitor", "Enable flow monitor", flow_monitor);
  cmd.Parse (argc, argv);

  // Validação dos parâmetros
  if (num_flows % 2 != 0 || num_flows > 20)
    {
      std::cout << "Error: nFlows DEVE ser um número par, 20 ou menos." << std::endl;
      return 1;
    }
  
  // Configura a semente do RNG para reprodutibilidade
  SeedManager::SetSeed (1);
  SeedManager::SetRun (run); 

  transport_prot = std::string ("ns3::") + transport_prot;

  // Configuração do TCP
  TypeId tcpTid;
  NS_ABORT_MSG_UNLESS (TypeId::LookupByNameFailSafe (transport_prot, &tcpTid), "TypeId " << transport_prot << " not found");
  Config::SetDefault ("ns3::TcpL4Protocol::SocketType", TypeIdValue (TypeId::LookupByName (transport_prot)));
  
  // Tempos de Simulação
  double start_time = 1.0; 
  double stop_time = 20.0;

  // Topologia: [source] -- [r1] --(gargalo)-- [r2] -- [dest1] (RTT Curto)
  //                                            |
  //                                            -- [dest2] (RTT Longo)
  
  NodeContainer nodes;
  nodes.Create (5); // 0=source, 1=r1, 2=r2, 3=dest1, 4=dest2
  NodeContainer n0n1 = NodeContainer (nodes.Get (0), nodes.Get (1)); // source -> r1
  NodeContainer n1n2 = NodeContainer (nodes.Get (1), nodes.Get (2)); // r1 -> r2 (gargalo)
  NodeContainer n2n3 = NodeContainer (nodes.Get (2), nodes.Get (3)); // r2 -> dest1
  NodeContainer n2n4 = NodeContainer (nodes.Get (2), nodes.Get (4)); // r2 -> dest2

  // Modelo de Erro
  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
  em->SetAttribute ("ErrorRate", DoubleValue (errorRate));

  // Configuração dos Links Ponto-a-Ponto
  
  // Link de Acesso (source <-> r1)
  PointToPointHelper p2pAccess;
  p2pAccess.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  p2pAccess.SetChannelAttribute ("Delay", StringValue ("0.01ms"));
  NetDeviceContainer d0d1 = p2pAccess.Install (n0n1);

  // Link de Gargalo (r1 <-> r2)
  PointToPointHelper p2pBottleneck;
  p2pBottleneck.SetDeviceAttribute ("DataRate", StringValue (dataRate));
  p2pBottleneck.SetChannelAttribute ("Delay", StringValue (delay));
  p2pBottleneck.SetDeviceAttribute ("ReceiveErrorModel", PointerValue (em));
  NetDeviceContainer d1d2 = p2pBottleneck.Install (n1n2);

  // Link para Dest1 (RTT Curto)
  PointToPointHelper p2pDest1;
  p2pDest1.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  p2pDest1.SetChannelAttribute ("Delay", StringValue ("0.01ms"));
  NetDeviceContainer d2d3 = p2pDest1.Install (n2n3);

  // Link para Dest2 (RTT Longo)
  PointToPointHelper p2pDest2;
  p2pDest2.SetDeviceAttribute ("DataRate", StringValue ("100Mbps"));
  p2pDest2.SetChannelAttribute ("Delay", StringValue ("50ms"));
  NetDeviceContainer d2d4 = p2pDest2.Install (n2n4);

  // Instalação da Pilha de Internet e Roteamento
  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper address;
  Ipv4InterfaceContainer i_dest1; // Interface de dest1
  Ipv4InterfaceContainer i_dest2; // Interface de dest2

  address.SetBase ("10.1.1.0", "255.255.255.0");
  address.Assign (d0d1);

  address.SetBase ("10.1.2.0", "255.255.255.0");
  address.Assign (d1d2);

  address.SetBase ("10.1.3.0", "255.255.255.0");
  i_dest1 = address.Assign (d2d3); // IP de dest1 será 10.1.3.2

  address.SetBase ("10.1.4.0", "255.255.255.0");
  i_dest2 = address.Assign (d2d4); // IP de dest2 será 10.1.4.2

  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  // Configuração das Aplicações
  uint16_t port = 50000;
  ApplicationContainer sinkApps;
  ApplicationContainer sourceApps;
  uint32_t halfFlows = num_flows / 2;

  // Instala Sinks (receptores)
  for (uint32_t i = 0; i < halfFlows; ++i)
    {
      // Sinks em dest1 (node 3)
      Address sinkAddress1 (InetSocketAddress (Ipv4Address::GetAny (), port + i));
      PacketSinkHelper pktSinkHelper1 ("ns3::TcpSocketFactory", sinkAddress1);
      sinkApps.Add (pktSinkHelper1.Install (nodes.Get (3)));

      // Sinks em dest2 (node 4)
      Address sinkAddress2 (InetSocketAddress (Ipv4Address::GetAny (), port + i + halfFlows));
      PacketSinkHelper pktSinkHelper2 ("ns3::TcpSocketFactory", sinkAddress2);
      sinkApps.Add (pktSinkHelper2.Install (nodes.Get (4)));
    }

  sinkApps.Start (Seconds (0.0));
  sinkApps.Stop (Seconds (stop_time));

  // Instala Sources (emissores)
  for (uint32_t i = 0; i < halfFlows; ++i)
    {
      // Fluxos para dest1
      AddressValue remote1 (InetSocketAddress (i_dest1.GetAddress (1), port + i));
      BulkSendHelper ftp1 ("ns3::TcpSocketFactory", Address ());
      ftp1.SetAttribute ("Remote", remote1);
      ftp1.SetAttribute ("MaxBytes", UintegerValue (0));
      sourceApps.Add (ftp1.Install (nodes.Get (0)));

      // Fluxos para dest2
      AddressValue remote2 (InetSocketAddress (i_dest2.GetAddress (1), port + i + halfFlows));
      BulkSendHelper ftp2 ("ns3::TcpSocketFactory", Address ());
      ftp2.SetAttribute ("Remote", remote2);
      ftp2.SetAttribute ("MaxBytes", UintegerValue (0));
      sourceApps.Add (ftp2.Install (nodes.Get (0)));
    }
  
  sourceApps.Start (Seconds (start_time));
  sourceApps.Stop (Seconds (stop_time));

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

  // Processamento de Saída
  if (flow_monitor)
    {
      monitor->CheckForLostPackets ();
      
      Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier> (flowHelper.GetClassifier ());
      FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats ();
      
      double duration = stop_time - start_time;
      
      double aggregateGoodputBps_dest1 = 0.0;
      double aggregateGoodputBps_dest2 = 0.0;
      uint32_t count_dest1 = 0;
      uint32_t count_dest2 = 0;

      for (auto const& [flowId, flowStats] : stats)
        {
          Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (flowId);

          // Filtra apenas fluxos de dados para dest1 (10.1.3.2)
          if (t.destinationAddress == "10.1.3.2")
            {
              double goodput_bps = (flowStats.rxBytes * 8.0) / duration;
              aggregateGoodputBps_dest1 += goodput_bps;
              count_dest1++;
            }
          // Filtra apenas fluxos de dados para dest2 (10.1.4.2)
          else if (t.destinationAddress == "10.1.4.2")
            {
              double goodput_bps = (flowStats.rxBytes * 8.0) / duration;
              aggregateGoodputBps_dest2 += goodput_bps;
              count_dest2++;
            }
        }
      
      // Calcula a média para cada grupo de fluxos
      double avg_dest1 = (count_dest1 > 0) ? aggregateGoodputBps_dest1 / count_dest1 : 0;
      double avg_dest2 = (count_dest2 > 0) ? aggregateGoodputBps_dest2 / count_dest2 : 0;

      // Imprime as linhas de média para os scripts de automação
      std::cout << "Goodput-dest1-avg: " << avg_dest1 << " bps" << std::endl;
      std::cout << "Goodput-dest2-avg: " << avg_dest2 << " bps" << std::endl;
    }

  Simulator::Destroy ();
  return 0;
}
