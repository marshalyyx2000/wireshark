<?xml version="1.0" encoding="UTF-8"?>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL">
  <Header id="sample" version="1.0"/>
  <IED name="TEMPLATE" desc="样例IED">
    <AccessPoint name="S1">
      <Server>
        <LDevice inst="LD0" desc="逻辑设备0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_Type" desc="逻辑节点零">
            <DataSet name="dsGOOSE1" desc="开关状态数据集">
              <FCDA ldInst="LD0" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="q" fc="ST"/>
            </DataSet>
            <DataSet name="dsSV1" desc="采样值数据集">
              <FCDA ldInst="LD0" prefix="" lnClass="TCTR" lnInst="1" doName="Amp" daName="instMag.i" fc="MX"/>
            </DataSet>
            <GSEControl name="gcb1" datSet="dsGOOSE1" confRev="1" type="GOOSE" appID="GOOSE_APP_1" desc="GOOSE控制块1"/>
            <SampledValueControl name="msvcb1" datSet="dsSV1" confRev="1" smvID="SV_ID_1" multicast="true" nofASDU="1" desc="SV控制块1">
              <SmvOpts sampleRate="true" refreshTime="true" sampleSynchronized="true"/>
            </SampledValueControl>
            <DOI name="Mod" desc="模式"/>
          </LN0>
          <LN lnClass="XCBR" inst="1" prefix="" lnType="XCBR_Type" desc="断路器1">
            <DOI name="Pos" desc="开关位置">
              <DAI name="stVal" desc="位置状态值"/>
              <DAI name="q" desc="品质"/>
            </DOI>
          </LN>
          <LN lnClass="TCTR" inst="1" prefix="" lnType="TCTR_Type" desc="电流互感器1">
            <DOI name="Amp" desc="电流">
              <SDI name="instMag">
                <DAI name="i" desc="电流瞬时值"/>
              </SDI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_Type" lnClass="LLN0">
      <DO name="Mod" type="ENC_Mod" desc="模式"/>
    </LNodeType>
    <LNodeType id="XCBR_Type" lnClass="XCBR">
      <DO name="Pos" type="DPC" desc="位置"/>
    </LNodeType>
    <LNodeType id="TCTR_Type" lnClass="TCTR">
      <DO name="Amp" type="SAV" desc="电流"/>
    </LNodeType>
    <DOType id="DPC" cdc="DPC">
      <DA name="stVal" bType="Dbpos" fc="ST" desc="双点位置"/>
      <DA name="q" bType="Quality" fc="ST" desc="品质"/>
    </DOType>
    <DOType id="SAV" cdc="SAV">
      <DA name="instMag" bType="Struct" type="AnalogueValue" fc="MX" desc="瞬时幅值"/>
    </DOType>
    <DOType id="ENC_Mod" cdc="ENC">
      <DA name="stVal" bType="Enum" fc="ST" desc="模式值"/>
    </DOType>
  </DataTypeTemplates>
</SCL>
