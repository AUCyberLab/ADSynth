# ADSynth: A Tool to Synthesize Realistic Active Directory Attack Graphs
ADSynth models Active Directory attack graphs based on set-to-set mapping, an intrinsic nature of AD systems. The tool generates the structure of AD graphs and security permissions following
design guidelines and security principles from Microsoft and prestigious organizations. In addition, ADSynth integrates common misconfigurations in AD administration, a cause for a myriad of AD attacks. Using our tool, users can generate realistic attack graphs for AD systems at various levels of security, ranging from vulnerable systems to extremely secure ones.

Please head to our <a href="https://aucyberlab.github.io/adsynthesizer/">website</a> for more details.

## REQUIREMENTS
* Python 3

## INSTALLATION
```
$ git clone https://github.com/adsynthesizer/ADSynth.git
$ pip install -r requirements.txt
```

## EXECUTION
1. Navigate to the folder ADSynth
```
$ cd <YOUR-PATH>/ADSynth
```
2. Run the program
```
python -m adsynth
```
(From any other directory, run `PYTHONPATH=<YOUR-PATH>/ADSynth python -m adsynth`.)
3. Run the following commands
* ```adconfig``` - Specify the level of security. There are 2 levels: Low or High. If you want to use your configuration (**highly recommended**), leave it as Customized.
* ```setparams``` - Set the parameters. Copy and paste the JSON file for your parameters. The template for it is in the file **params_template.json**. Details of parameters are in **params_list.xlsx** or on our <a href="https://aucyberlab.github.io/adsynthesizer/">website</a>.
* ```generate``` - Generate the AD attack graph

    <b>[OPTIONAL]</b>
* ```neo4jconfig``` - Connect to Neo4J database
* ```importdb``` - Import generated datasets to Neo4J. Before using this feature, please install the APOC library. Information can be found in the document **Neo4J_guides.pdf**.

# Output graphs
The generated graphs are located in the folder **generated_datasets**. The output format is <a href="https://neo4j.com/labs/apoc/4.1/export/json/">Neo4J format</a>.

The output should include one JSON object per line, either a node or relationship, containing id, type, properties, and labels.

The JSON file can be loaded in Neo4J using APOC library. After that, the graph can be visualised in <a href="https://bloodhound.readthedocs.io/en/latest/">BloodHound</a>.

For example:
* Node: {"id":"0","labels":["Base","User"],"properties":{...},"type":"node"}

    ```type``` signifies this is a JSON object for a node.

    ```id```: node ID

    ```labels```: object types, please disregard the first label <i>Base</i>. In the example, this is a User node.


* Edge: {"type":"relationship","id":"r_258","properties":{},"start":{"id":"70","labels":[...]},"end":{"id":"67","labels":[...]},"label":"MemberOf"}

    ```type``` signifies that this is a JSON object for a relationship/edge.

    ```id```: edge ID

    ```start```: a JSON object containing the ID of the starting node and its labels.

    ```end```: a JSON object containing the ID of the ending node and its labels.

    ```label```: the relationship between 2 objects. This can be used to indicate permissions, group membership, or set ownership (specifying if an object belongs to an organisational unit OU, <i><b>equivalent to an element belonging to a set</b></i>).

# ACKNOWLEDGEMENT
We acknowledge the previous work on AD systems from DBCreator, ADSimulator, Microsoft, and other sources.
We make citations on the parts we reference.
