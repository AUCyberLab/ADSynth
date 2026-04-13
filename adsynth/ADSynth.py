# Requirements - pip install neo4j-driver
# This script is used to create randomized sample databases.
# Commands
# 	dbconfig - Set the credentials and URL for the database you're connecting too
#	connect - Connects to the database using supplied credentials
# 	setparams - Set the settings JSON file
# 	setdomain - Set the domain name
# 	cleardb - Clears the database and sets the schema properly
#	generate - Connects to the database, clears the DB, sets the schema, and generates random data

# from neo4j import GraphDatabase
import getpass
import cmd
from collections import defaultdict
import uuid
import time
import random
import os
from adsynth.default_ad_system.default_acls import create_administrators_acls, create_default_AllExtendedRights, create_default_GenericAll, create_default_GenericWrite, create_default_dc_groups_acls, create_default_groups_acls, create_default_owns, create_default_users_acls, create_default_write_dacl_owner, create_domain_admins_acls, create_enterprise_admins_acls
from adsynth.default_ad_system.default_gpos import apply_default_gpos, create_default_gpos
from adsynth.default_ad_system.default_groups import create_adminstrator_memberships, create_default_groups, generate_default_member_of
from adsynth.default_ad_system.default_ous import create_domain_controllers_ou
from adsynth.default_ad_system.default_users import generate_administrator, generate_default_account, generate_guest_user, generate_krbtgt_user, link_default_users_to_domain
from adsynth.default_ad_system.domains import create_domain
from adsynth.azure_ad_system.az_default_tenants import az_create_tenant
from adsynth.azure_ad_system.az_default_subscriptions import az_create_subscriptions
from adsynth.azure_ad_system.az_default_roles import az_create_roles
from adsynth.azure_ad_system.az_default_users import az_create_users
from adsynth.azure_ad_system.az_default_groups import az_create_groups
from adsynth.azure_ad_system.az_default_service_principals import az_create_service_principals
from adsynth.azure_ad_system.az_default_applications import az_create_applications
from adsynth.azure_ad_system.az_default_relationships import az_assign_group_memberships, az_assign_roles
from adsynth.azure_ad_system.az_default_permissions import az_create_permissions
from adsynth.azure_ad_system.az_default_management_groups import az_create_management_groups
from adsynth.azure_ad_system.az_default_key_vaults import az_create_key_vaults
from adsynth.azure_ad_system.az_default_vms import az_create_vms
from adsynth.entities.acls import cs
from adsynth.helpers.about import print_adsynth_software_information
from adsynth.helpers.getters import get_num_tiers, get_single_int_param_value
from adsynth.helpers.objects import segregate_list
from adsynth.synthesizer.misconfig import create_misconfig_group_nesting, create_misconfig_permissions_on_groups, create_misconfig_permissions_on_individuals, create_misconfig_sessions
from adsynth.synthesizer.object_placement import nest_groups, place_admin_users_in_tiers, place_computers_in_tiers, place_normal_users_in_tiers, place_users_in_groups
from adsynth.synthesizer.objects import create_admin_groups, create_groups, create_kerberoastable_users, generate_computers, generate_dcs, generate_users
from adsynth.synthesizer.ou_structure import create_ad_skeleton
from adsynth.synthesizer.permissions import assign_administration_to_admin_principals, assign_local_admin_rights, create_control_management_permissions
from adsynth.synthesizer.security_policies import apply_gpos, apply_restriction_gpos, create_gpos_container, place_gpos_in_container
from adsynth.synthesizer.sessions import create_dc_sessions, create_sessions
from adsynth.utils.data import get_names_pool, get_surnames_pool, get_parameters_from_json, get_domains_pool
from adsynth.utils.domains import get_domain_dn
from adsynth.utils.parameters import print_all_parameters, get_int_param_value, get_perc_param_value
from adsynth.adsynth_templates.default_config import DEFAULT_CONFIGURATIONS
from adsynth.DATABASE import *
from adsynth.azure_ai.smart_params import SmartParameterGenerator
import json
from timeit import default_timer as timer
from datetime import datetime
from adsynth.synthesizer.hybrid_seam import (
    create_sync_links, create_user_synced_to_edges
)
from adsynth.synthesizer.nhi import create_non_humans
from adsynth.hybrid_system.invariant_validators import (
    validate_graph_invariants, print_validation_report
)
from adsynth.synthesizer.hybrid_seam import create_sync_links, create_user_synced_to_edges
from adsynth.synthesizer.nhi import create_non_humans
from adsynth.hybrid_system.invariant_validators import validate_graph_invariants, print_validation_report
from adsynth.synthesizer.hybrid_seam import (
    create_sync_links, create_user_synced_to_edges
)
from adsynth.synthesizer.nhi import create_non_humans
from adsynth.hybrid_system.invariant_validators import (
    validate_graph_invariants, print_validation_report
)
from adsynth.synthesizer.permissions_hybrid import run_hybrid_permissions_phase
from adsynth.hybrid_system.seam_metrics import (
	compute_seam_metrics, print_seam_metrics_report, export_metrics_json
)

SYNC_RELATIONSHIPS = {}  # Maps AD object IDs to Azure object IDs
HYBRID_OBJECTS = {}      # Tracks objects that exist in both environments
CLOUD_ONLY_OBJECTS = {}  # Tracks cloud-only objects
ON_PREM_ONLY_OBJECTS = {} # Tracks on-premises only objects

def reset_DB():
	NODES.clear()
	EDGES.clear()

	for item in DATABASE_ID:
		DATABASE_ID[item].clear()

	dict_edges.clear()

	for item in NODE_GROUPS:
		NODE_GROUPS[item].clear()

	GPLINK_OUS.clear()

	GROUP_MEMBERS.clear()

	SECURITY_GROUPS.clear()

	LOCAL_ADMINS.clear()

	ADMIN_USERS.clear()

	ENABLED_USERS.clear() # processed names # Tiered

	DISABLED_USERS.clear() # processed names

	PAW_TIERS.clear() # Tiered

	S_TIERS.clear() # Tiered

	WS_TIERS.clear() # Tiered

	COMPUTERS.clear() # All

	ridcount.clear()

	KERBEROASTABLES.clear() # processed names
	
	SYNC_RELATIONSHIPS.clear()
	HYBRID_OBJECTS.clear()
	CLOUD_ONLY_OBJECTS.clear()
	ON_PREM_ONLY_OBJECTS.clear()

neo4j = None
def safe_import_neo4j():
	global neo4j
	try:
		import neo4j as neo4j_lib
		neo4j = neo4j_lib
		return neo4j
	except ImportError:
		print("The 'neo4j' module is not installed. Please install it using 'pip install -r requirements.txt'.")
		return None
	
class Messages():
	def title(self):
		print(
		"""
																	   ,----,            
														   ,--.      ,/   .`|       ,--, 
   ,---,           ,---,      .--.--.                    ,--.'|    ,`   .'  :     ,--.'| 
  '  .' \        .'  .' `\   /  /    '.      ,---,   ,--,:  : |  ;    ;     /  ,--,  | : 
 /  ;    '.    ,---.'     \ |  :  /`. /     /_ ./|,`--.'`|  ' :.'___,/    ,',---.'|  : ' 
:  :       \   |   |  .`\  |;  |  |--`,---, |  ' :|   :  :  | ||    :     | |   | : _' | 
:  |   /\   \  :   : |  '  ||  :  ;_ /___/ \.  : |:   |   \ | :;    |.';  ; :   : |.'  | 
|  :  ' ;.   : |   ' '  ;  : \  \    `.  \  \ ,' '|   : '  '; |`----'  |  | |   ' '  ; : 
|  |  ;/  \   \\'   | ;  .  |  `----.   \  ;  `  ,''   ' ;.    ;    '   :  ; '   |  .'. | 
'  :  | \  \ ,'|   | :  |  '  __ \  \  |\  \    ' |   | | \   |    |   |  ' |   | :  | ' 
|  |  '  '--'  '   : | /  ;  /  /`--'  / '  \   | '   : |  ; .'    '   :  | '   : |  : ; 
|  :  :        |   | '` ,/  '--'.     /   \  ;  ; |   | '`--'      ;   |.'  |   | '  ,/  
|  | ,'        ;   :  .'      `--'---'     :  \  \\'   : |          '---'    ;   : ;--'   
`--''          |   ,.'                      \  ' ;;   |.'                   |   ,/       
			   '---'                         `--` '---'                     '---'        
																						 
																																															  
		"""
		)
		print("Synthesizing realistic Active Directory attack graphs\n")
		print("==================================================================")

	# Ref: DBCreator
	def input_default(self, prompt, default):
		return input("%s [%s] " % (prompt, default)) or default
	
	def input_default_password(self, prompt, default, hide_input=False):
		if hide_input:
			# Use getpass to securely input passwords
			prompt_with_default = f"{prompt} [{default}] "
			return getpass.getpass(prompt_with_default) or default
		else:
			# Regular input for other types of data
			return input(f"{prompt} [{default}] ") or default
	
	def input_security_level(self, prompt, default):
		user_input = input("%s [%s] " % (prompt, default)) or default
		if not user_input:
			return default
		
		try:
			user_input = int(user_input)
			if user_input in [1, 2, 3]:
					return user_input
		except:
			pass
		return default

	# Ref: DBCreator
	def input_yesno(self, prompt, default):
		temp = input(prompt + " " + ("Y" if default else "y") + "/" + ("n" if default else "N") + " ")
		if temp == "y" or temp == "Y":
			return True
		elif temp == "n" or temp == "N":
			return False
		return default



class MainMenu(cmd.Cmd):
	# The main functions to generate realistic Active Directory attack graphs using metagraphs belong to ADSynth.
	# In case of code re-use from previous work, LICENSING is provided at the top of a file
	# In case of code modification or ideas related to fundamental concepts of Active Directory, clear references are mentioned at the top of such functions.

	def __init__(self):
		self.m = Messages()
		self.url = "bolt://localhost:7687"
		self.username = "neo4j"
		self.password = "neo4j"
		self.use_encryption = False
		self.driver = None
		self.connected = False
		self.old_domain = None
		self.domain = "TESTLAB.LOCALE"
		self.current_time = int(time.time())
		self.base_sid = "S-1-5-21-883232822-274137685-4173207997"
		self.first_names = get_names_pool()
		self.last_names = get_surnames_pool()
		self.domain_names = get_domains_pool()
		self.parameters_json_path = "DEFAULT"
		self.parameters = DEFAULT_CONFIGURATIONS
		self.json_file_name = None
		self.level = "Customized"
		self.dbname = None

		cmd.Cmd.__init__(self)

	
	def cmdloop(self):
		while True:
			self.m.title()
			self.do_help("")
			try:
				try:
					cmd.Cmd.cmdloop(self)
				except EOFError:
					break
					return True

			except KeyboardInterrupt:
				if self.driver is not None:
					self.driver.close()
				return True

	
	def help_adconfig(self):
		print("Configure AD level of security")

	def help_neo4jconfig(self):
		print("Configure Neo4J database")

	def help_connect(self):
		print("Test connection to the database and verify credentials")

 
	def help_setdomain(self):
		print("Set domain name (default 'TESTLAB.LOCALE')")

 
	def help_cleardb(self):
		print("Clear the Neo4J database and set constraints")

 
	def help_generate(self):
		print("Generate an Active Directory attack graph based on the given parameters")

	def help_generate_azure(self):
		print("Generate an Azure Active Directory attack graph based on the given parameters")


	def help_setparams(self):
		print("Import the settings JSON file containing the parameters for the graph generation")

	def help_smartparams(self):
		print("Generate parameters from natural language description")

	def help_about(self):
		print("View information about adsynth")

	def help_importdb(self):
		print("Import a JSON file to Neo4J")

 
	def help_exit(self):
		print("Exit")
	
	# def help_remove_constraints(self):
	#     print("Remove Neo4J constraints")
	  

	def do_about(self, args):
		print_adsynth_software_information()

	def do_adconfig(self, args):
		# Level of security
		security_settings = {
			1: "Customized",
			2: "Low",
			3: "High"
		}
		security_settings_code = {
			"Customized": 1,
			"Low": 2,
			"High": 3
		}

		level_code = self.m.input_security_level(
			"Enter level of security  (type a number 1/2/3) - Cuztomized (1), Low (2), High (3): ", security_settings_code[self.level])
		self.level = security_settings[level_code]
		print("Level of Security: {}".format(self.level))
	

	def do_neo4jconfig(self, args):
		global neo4j
		neo4j = safe_import_neo4j()
		if neo4j is None:
			return
		
		print("Current Settings")
		print("DB Url: {}".format(self.url))
		print("DB Username: {}".format(self.username))
		print("DB Password: {}".format(self.password))
		print("Use encryption: {}".format(self.use_encryption))
		print("")

		self.url = self.m.input_default("Enter DB URL", self.url)
		self.username = self.m.input_default(
			"Enter DB Username", self.username)
		self.password = self.m.input_default_password(
			"Enter DB Password", self.password)
		self.use_encryption = self.m.input_yesno(
			"Use encryption?", self.use_encryption)


		print("")
		print("Confirmed Settings:")
		print("DB Url: {}".format(self.url))
		print("DB Username: {}".format(self.username))
		print("DB Password: {}".format(self.password))
		print("Use encryption: {}".format(self.use_encryption))
		print("")
		print("Testing DB Connection")
		self.test_db_conn()

 
	def do_setdomain(self, args):
		passed = args
		if passed != "":
			try:
				self.domain = passed.upper()
				return
			except ValueError:
				pass

		self.domain = self.m.input_default("Domain", self.domain).upper()
		print("")
		print("New Settings:")
		print("Domain: {}".format(self.domain))


	def do_exit(self, args):
		raise KeyboardInterrupt

 
	def do_connect(self, args):
		self.test_db_conn()


	def remove_constraints(self, session):
		# Remove constraint - From DBCreator
		print("Resetting Schema")
		for constraint in session.run("SHOW CONSTRAINTS"):
			session.run("DROP CONSTRAINT {}".format(constraint['name']))

		icount = session.run(
			"SHOW INDEXES YIELD name RETURN count(*)")
		for r in icount:
			ic = int(r['count(*)'])
				
		while ic >0:
			print("Deleting indices from database")
		
			showall = session.run(
				"SHOW INDEXES")
			for record in showall:
				name = (record['name'])
				session.run("DROP INDEX {}".format(name))
			ic = 0
		 
		# Setting constraints
		print("Setting constraints")

		constraints = [
				"CREATE CONSTRAINT FOR (n:Base) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:Domain) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:Computer) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:User) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:OU) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:GPO) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:Compromised) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:Group) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:Container) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:AZTenant) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:AZSubscription) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:AZRole) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:AZUser) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:AZGroup) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:AZServicePrincipal) REQUIRE n.id IS UNIQUE;",
				"CREATE CONSTRAINT FOR (n:AZApp) REQUIRE n.id IS UNIQUE;"
		]

		for constraint in constraints:
			try:
				session.run(constraint)
			except:
				continue
		

		session.run("match (a) -[r] -> () delete a, r")
		session.run("match (a) delete a")


	def do_cleardb(self, args):
		if not self.connected:
			print("Not connected to database. Use connect first")
			return

		print("Clearing Database")
		d = self.driver
		session = d.session()

		# Delete nodes and edges with batching into 10k objects - From DBCreator
		total = 1
		while total > 0:
			result = session.run(
				"MATCH (n) WITH n LIMIT 10000 DETACH DELETE n RETURN count(n)")
			for r in result:
				total = int(r['count(n)'])
		
		self.remove_constraints(session)

		session.close()

		print("DB Cleared and Schema Set")
	

	def do_setparams(self, args):
		passed = args
		if passed != "":
			try:
				json_path = passed
				self.parameters = get_parameters_from_json(json_path)
				self.parameters_json_path = json_path
				print_all_parameters(self.parameters)
				return
			except ValueError:
				pass

		json_path = self.m.input_default("Parameters JSON file (copy and paste the full path of your parameter JSON file)", self.parameters_json_path)
		self.parameters = get_parameters_from_json(json_path)
		if self.parameters == DEFAULT_CONFIGURATIONS:
			self.parameters_json_path = "DEFAULT"
		else:
			self.parameters_json_path = json_path

		print_all_parameters(self.parameters)

	def do_smartparams(self, args):
		"""Generate parameters using Azure AI from natural language"""
	
		if not args.strip():
			prompt = input("Describe your organization (e.g., 'Medium healthcare org with high security'): ")
		else:
			prompt = args
	
		print(f"Generating parameters for: {prompt}")
	
		try:
			generator = SmartParameterGenerator()
			ai_params = generator.generate_parameters(prompt)
		
			if ai_params:
				print("\n" + "="*50)
				print("AI GENERATED PARAMETERS:")
				print("="*50)
				print(json.dumps(ai_params, indent=2))
				
				# Validate that we have the minimum required parameters
				required_keys = ["User", "Computer", "Admin"]
				missing_keys = [key for key in required_keys if key not in ai_params]
				
				if missing_keys:
					print(f"\nWarning: Missing required sections: {missing_keys}")
					print("Using default configuration as base...")
					
					# Start with defaults and update with AI params
					from adsynth.adsynth_templates.default_config import DEFAULT_CONFIGURATIONS
					merged_params = DEFAULT_CONFIGURATIONS.copy()
					
					# Deep update function
					def deep_update(base, update):
						for key, value in update.items():
							if key in base and isinstance(base[key], dict) and isinstance(value, dict):
								deep_update(base[key], value)
							else:
								base[key] = value
					
					deep_update(merged_params, ai_params)
					final_params = merged_params
				else:
					# AI params are complete enough to use directly
					final_params = ai_params
				
				# Validate critical parameters
				if (final_params.get("User", {}).get("nUsers", 0) > 0 and 
					final_params.get("Computer", {}).get("nComputers", 0) > 0):
					
					self.parameters = final_params
					self.parameters_json_path = "AI_GENERATED"
					
					print("\n" + "="*50)
					print("FINAL PARAMETERS TO BE USED:")
					print("="*50)
					print_all_parameters(self.parameters)
					
					# Ask if user wants to save
					save = self.m.input_yesno("\nSave these parameters to file?", True)
					if save:
						# Create filename from prompt
						safe_prompt = "".join(c for c in prompt if c.isalnum() or c in (' ', '-', '_')).strip()
						safe_prompt = safe_prompt.replace(' ', '_')[:30]
						filename = f"ai_generated_{safe_prompt}.json"
						
						# Ensure the directory exists
						os.makedirs("adsynth/experiment_params", exist_ok=True)
						filepath = f"adsynth/experiment_params/{filename}"
						
						with open(filepath, 'w') as f:
							json.dump(final_params, f, indent=4)
						print(f"Parameters saved to {filepath}")
					
					print("\nParameters generated and loaded successfully!")
					
				else:
					print("\nGenerated parameters invalid (missing users or computers).")
					print("Please check your organization description and try again.")
					print("Keeping current parameters.")
					
			else:
				print("\nFailed to generate parameters.")
				print("Possible issues:")
				print("- Check Azure AI configuration in .env file")
				print("- Verify API key and endpoint are correct")
				print("- Check internet connectivity")
				print("Keeping current parameters.")
				
		except Exception as e:
			print(f"\nError occurred: {e}")
			print("This might be due to:")
			print("- Missing or incorrect Azure OpenAI credentials")
			print("- Network connectivity issues")
			print("- API quota exceeded")
			print("Keeping current parameters.")

	def test_db_conn(self):
		if neo4j is None:
			print("Please setup Neo4J database first using 'neo4jconfig'")
			return
		
		try:
			if self.driver is not None:
				self.driver.close()
			self.driver = neo4j.GraphDatabase.driver(
				self.url, auth=(self.username, self.password), encrypted=self.use_encryption)
			with self.driver.session() as session:
				result = session.run("RETURN 1")
			self.connected = True
			print("Database Connection Successful!")
		except neo4j.exceptions.AuthError:
			print("Authentication failed: Incorrect username or password.")
		except neo4j.exceptions.ServiceUnavailable:
			print("Neo4J Service unavailable: Unable to connect to the database. Please make sure you have activated Neo4J.")
		except:
			self.connected = False
			print("Database Connection Failed. Check your settings.")

	def do_importdb(self, args):
		"""Import a JSON file to Neo4j using APOC (manual permissions setup required)"""
		if not self.connected:
			print("Neo4j connection has not been configured yet. Please run 'neo4jconfig' first.")
			return

		print("Please input the name of a JSON file in the folder 'generated_datasets' (excluding the file extension).")
		print("Or provide the full path to your intended JSON file.")
		print("If you want to import the dataset you have just generated in this terminal, please press Enter.")
		
		dataset_name = input("Dataset to be imported: ")
		
		if not dataset_name:
			if self.dbname is None:
				print("No dataset generated recently")
				return
			filename = f"{self.dbname}.json"
		else:
			if dataset_name.endswith('.json'):
				filename = dataset_name
			else:
				filename = f"{dataset_name}.json"
		
		# Check if file exists in generated_datasets
		file_path = f"{os.getcwd()}/generated_datasets/{filename}"
		if not os.path.exists(file_path):
			print(f"File not found: {file_path}")
			return
		
		try:
			self.test_db_conn()
			if not self.connected:
				print("Failed to connect to Neo4j database")
				return
		except Exception as e:
			print(f"Database connection error: {e}")
			return

		session = self.driver.session()
		
		try:
			# Clear database first
			print("Clearing existing database...")
			self.do_cleardb("")
			
			print("========== APOC IMPORT PROCESS ==========")
			print(f"Importing: {filename}")
			
			# Neo4j import directory
			neo4j_import_dir = "/var/lib/neo4j/import/"
			target_path = os.path.join(neo4j_import_dir, filename)
			
			# Simple copy (assumes permissions are set correctly)
			import shutil
			try:
				shutil.copy2(file_path, target_path)
				print(f"Copied to: {target_path}")
			except Exception as e:
				print(f"Failed to copy file: {e}")
				print(f"Please manually copy the file:")
				print(f"sudo cp {file_path} {target_path}")
				print(f"sudo chmod 644 {target_path}")
				return
			
			# Use APOC with just the filename
			file_url = f"file:///{filename}"
			print(f"Loading from: {file_url}")
			
			# Import nodes
			print("Importing nodes...")
			node_query = f"""
			CALL apoc.load.json('{file_url}') 
			YIELD value
			WITH value
			WHERE value.type = "node"
			WITH value.labels as labels, value.properties as props, value.id as nodeId
			CALL apoc.create.node(labels, apoc.map.setKey(props, 'id', nodeId)) 
			YIELD node
			RETURN count(node) as nodeCount
			"""
			
			node_result = session.run(node_query)
			node_count = node_result.single()['nodeCount']
			print(f"Created {node_count} nodes")
			
			# Import relationships
			print("Importing relationships...")
			rel_query = f"""
			CALL apoc.load.json('{file_url}') 
			YIELD value
			WITH value
			WHERE value.type = "relationship"
			MATCH (start {{id: value.start.id}}), (end {{id: value.end.id}})
			CALL apoc.create.relationship(start, value.label, value.properties, end) 
			YIELD rel
			RETURN count(rel) as relCount
			"""
			
			rel_result = session.run(rel_query)
			rel_count = rel_result.single()['relCount']
			print(f"Created {rel_count} relationships")
			
			print("========== IMPORT COMPLETED ==========")
			print(f"Total nodes: {node_count}")
			print(f"Total relationships: {rel_count}")
			
			# Clean up copied file
			try:
				os.remove(target_path)
				print("Cleaned up temporary file")
			except:
				print(f"Note: Temporary file remains at {target_path}")
				
		except Exception as e:
			print(f"APOC import failed: {e}")
			print("Make sure APOC plugin is installed and Neo4j is running")
			
		finally:
			session.close()

	def help_importdb(self):
		print("Import a JSON file to Neo4j using APOC")
		print("Usage: importdb [filename]")
		print("  - Copies file to /var/lib/neo4j/import/")
		print("  - Requires write permissions to Neo4j import directory")
		print("  - Run this first to set permissions:")
		print("    sudo chmod 755 /var/lib/neo4j/import/")
		print("    sudo chown $USER:$USER /var/lib/neo4j/import/")

	def do_generate(self, args):
		
		print(self.level)
		passed = args
		if passed != "":
			try:
				self.json_file_name = passed
			except ValueError:
				self.json_file_name = None

		# Disable Neo4J from ADSynth
		# self.test_db_conn()
		# self.do_cleardb("a")

		reset_DB()
		
		self.generate_data()
		self.old_domain = self.domain


	def do_generate_azure(self, args):

		print("Generating Azure Active Directory graph")
		self.generate_data_azure()


	def generate_data(self):
		start_ = timer()
		seed_number = get_single_int_param_value("seed", self.parameters)
		if seed_number > 0:
			random.seed(seed_number)

		# if not self.connected:
		#     print("Not connected to database. Use connect first")
		#     return
		
		domain_dn = get_domain_dn(self.domain)

		nTiers = get_num_tiers(self.parameters) 

		# RIDs below 1000 are used for default principals.
		# RIDs of other objects should start from 1000.
		# Idea Ref: DBCreator and https://www.itprotoday.com/security/q-what-are-exact-roles-windows-accounts-sid-and-more-specifically-its-rid-windows-security
		ridcount.extend([1000])  

		computers = []
		
		users = []

		convert_to_digraph = get_single_int_param_value("convert_to_directed_graphs", self.parameters)
		
		# session = self.driver.session()

		print(f"Initiating the Active Directory Domain - {self.domain}")
		functional_level = create_domain(self.domain, self.base_sid, domain_dn, self.parameters) # Ref: ADSimulator, DBCreator
		
		print("Building the fundamental framework of a tiered Active Directory model")
		create_ad_skeleton(self.domain, self.base_sid, self.parameters, nTiers)

		# -------------------------------------------------------------
		# Active Directory Default OUs, Groups and GPOs
		# Ref: DBCreator and ADSimulator have produced some default AD objects and relationships in their code
		# Utilising Microsoft documentation as a knowledge base, I migrated their codes into ADSynth built-in database.
		
		print("Creating the default domain groups")
		create_default_groups(self.domain, self.base_sid, self.old_domain) # Ref: ADSimulator, DBCreator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
		
		print("Creating the admin groups")
		create_admin_groups(self.domain, self.base_sid, nTiers)
		
		ddp = cs(str(uuid.uuid4()), self.base_sid).upper()
		ddcp = cs(str(uuid.uuid4()), self.base_sid).upper()
		dcou = cs(str(uuid.uuid4()), self.base_sid).upper()
		gpos_container = cs(str(uuid.uuid4()), self.base_sid).upper()

		print("Creating GPOs container")
		create_gpos_container(self.domain, domain_dn, gpos_container)
		
		print("Creating default GPOs")
		create_default_gpos(self.domain, domain_dn, ddp, ddcp) # Ref: DBCreator, ADSimulator and Microsoft, https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpod/566e983e-3b72-4b2d-9063-a00ebc9514fd

		print("Creating Domain Controllers OU")
		create_domain_controllers_ou(self.domain, domain_dn, dcou) # Ref: DBCreator, ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-of-default-containers-and-ous

		print("Applying Default GPOs")
		apply_default_gpos(self.domain, ddp, ddcp, dcou) # Ref: DBCreator, ADSimulator

		
		# ENTERPRISE ADMINS
		# Adding Ent Admins -> High Value Targets
		print("Creating Enterprise Admins ACLs")
		create_enterprise_admins_acls(self.domain) # Ref: DBCreator, ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups


		# ADMINISTRATORS
		# Adding Administrators -> High Value Targets
		print("Creating Administrators ACLs")
		create_administrators_acls(self.domain) # Ref: DBCreator, ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups


		# DOMAIN ADMINS
		# Adding Domain Admins -> High Value Targets
		print("Creating Domain Admins ACLs")
		create_domain_admins_acls(self.domain) # Ref: DBCreator, ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups


		# DC Groups
		# Extra ENTERPRISE READ-ONLY DOMAIN CONTROLLERS
		print("Generating DC groups ACLs")
		create_default_dc_groups_acls(self.domain) # Ref: DBCreator, ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups

		# DOMAIN CONTROLLERS
		# Ref: ADSimulator, DBCreator and Microsoft, https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/c4012a57-16a9-42eb-8f64-aa9e04698dca
		print("Creating Domain Controllers")
		dc_properties_list, domain_controllers = generate_dcs(self.domain, self.base_sid, domain_dn, dcou, self.current_time, self.parameters, functional_level) # O(1)

		# -------------------------------------------------------------
		# GPOs - Creating GPOs for the root OUs in a Tier Model
		print("Applying GPOs to critical OUs and tiers")
		apply_gpos(self.domain, self.base_sid, nTiers) # Ref: Russell Smith, https://petri.com/keep-active-directory-secure-using-privileged-access-workstations/, https://volkandemirci.org/2022/01/17/privileged-access-workstations-kurulumu-ve-yapilandirilmasi-2/
		

		# Impose restriction on non-privileged OU
		apply_restriction_gpos(self.domain, self.base_sid, self.parameters)


		# Place all GPOs in the GPOs container
		place_gpos_in_container(self.domain, gpos_container)
			
		# -------------------------------------------------------------
		# DEFAULT USERS and group relationships
		# Ref: ADSimulator produced these in their code
		# Utilising Microsoft documentation as a knowledge base, I migrated their code into ADSynth built-in database.
		# https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts
		print("Generating default users")
		generate_guest_user(self.domain, self.base_sid, self.parameters)
		generate_default_account(self.domain, self.base_sid, self.parameters)
		generate_administrator(self.domain, self.base_sid, self.parameters)
		generate_krbtgt_user(self.domain, self.base_sid, self.parameters)
		link_default_users_to_domain(self.domain, self.base_sid)
		
		# Ref: ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-default-user-accounts
		print("Creating ACLs for default users")
		create_default_users_acls(self.domain, self.base_sid)

		# Ref: ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
		# Adminstrator account is Member of High value groups
		print("Creating memberships for Administrator group")
		create_adminstrator_memberships(self.domain)

		# Ref: ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
		print("Assigning members to default groups")
		generate_default_member_of(self.domain, self.base_sid, self.old_domain)

		# Ref: ADSimulator and Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory
		print("Creating ACLs for default groups")
		create_default_groups_acls(self.domain, self.base_sid)


		# -------------------------------------------------------------
		# Creating users
		num_users = get_int_param_value("User", "nUsers", self.parameters)
		print(f"Creating {num_users} users")

		# Get a list of enabled and disabled users
		users, disabled_users = generate_users(self.domain, self.base_sid, num_users, self.current_time, self.first_names, self.last_names, self.parameters) # Ref: ADSimulator, DBCreator

		# Segragate admin and regular users
		perc_admin = get_perc_param_value("Admin", "Admin_Percentage", self.parameters)
		all_admins, all_enabled_users = segregate_list(users, [perc_admin, 100 - perc_admin])

		# Segregate admins and misconfigured admins in regular Users OU
		misconfig_admin_regular_perc = get_perc_param_value("nodeMisconfig", "admin_regular", self.parameters)
		if misconfig_admin_regular_perc > 50:
			misconfig_admin_regular_perc = DEFAULT_CONFIGURATIONS["nodeMisconfig"]["admin_regular"]
		admin, misconfig_admin = segregate_list(all_admins, [100 - misconfig_admin_regular_perc, misconfig_admin_regular_perc])

		# Segregate regular users, misconfigured users in Admin OU and in Computers OU
		misconfig_user_comp_perc = get_perc_param_value("nodeMisconfig", "user_comp", self.parameters)
		if misconfig_admin_regular_perc + misconfig_user_comp_perc > 50:
			misconfig_admin_regular_perc = DEFAULT_CONFIGURATIONS["nodeMisconfig"]["admin_regular"]
			misconfig_user_comp_perc = DEFAULT_CONFIGURATIONS["nodeMisconfig"]["user_comp"]
		enabled_users, misconfig_regular_users, misconfig_users_comps = \
			segregate_list(all_enabled_users, [100 - misconfig_admin_regular_perc - misconfig_user_comp_perc, misconfig_admin_regular_perc, misconfig_user_comp_perc])
 

		# -------------------------------------------------------------
		# Creating COMPUTERS
		num_computers = get_int_param_value("Computer", "nComputers", self.parameters)
		print("Generating", str(num_computers), "computers")

		# Ref: ADSimulator, DBCreator, BadBlood
		#      Microsoft, https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices
		computers, PAW, Servers, Workstations = generate_computers(self.domain, self.base_sid, num_computers, computers, self.current_time, self.parameters)

		Workstations, misconfig_workstations = segregate_list(Workstations, [100 - misconfig_user_comp_perc, misconfig_user_comp_perc])
		place_computers_in_tiers(self.domain, self.base_sid, nTiers, self.parameters, PAW, Servers, Workstations, misconfig_users_comps)

		
		# -------------------------------------------------------------
		# Admin Users
		print("Allocate Admin Users to tiers")

		# Retrieve members of server operators and print operators
		# to later generate sessions on Domain Controllers
		server_operators = [] # Server Operators 
		print_operators = []  # Print Operators 
		
		place_admin_users_in_tiers(self.domain, self.base_sid, nTiers, admin, misconfig_regular_users, server_operators, print_operators, self.parameters)
		
		# Non-admin Users
		print("Allocate non-admin users to tiers")
		place_normal_users_in_tiers(self.domain, enabled_users, disabled_users, misconfig_admin, misconfig_workstations, nTiers)


		# -------------------------------------------------------------
		# Creating GROUPS
		print("Creating distribution groups and security groups")
		num_regular_groups = create_groups(self.domain, self.base_sid, self.parameters, nTiers)
		
		print("Nesting groups")
		nest_groups(self.domain, self.parameters) # Ref: DBCreator and ADSimulator

		# Adding Users to Groups
		# Admin users have been place into admistrative tiers. Now comes the normal users
		print("Adding users to groups")
		it_users = place_users_in_groups(self.domain, nTiers, self.parameters)


		# -------------------------------------------------------------
		print("Generate sessions")
		create_sessions(nTiers, PAW_TIERS, S_TIERS, WS_TIERS, self.parameters)
		
		print("Generate cross-tier sessions")
		create_misconfig_sessions(nTiers, self.level, self.parameters, len(enabled_users) + len(admin))

		# Print Operators and Server Operators can log into Domain Controllers
		# Idea Ref: Microsoft, https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups
		print("Print Operators and Server Operators can log into Domain Controllers")
		create_dc_sessions(domain_controllers, server_operators, print_operators) # O(num of Domain Controllers)
	
		
		# -------------------------------------------------------------
		# Generate non-ACL Permissions
		print("Generating non-ACL permissions")
		create_control_management_permissions(self.domain, nTiers, False, self.parameters, convert_to_digraph)
		
		print("Generating misconfigured non-ACL permissions on individuals")
		create_misconfig_permissions_on_individuals(nTiers, ADMIN_USERS, ENABLED_USERS, self.level, self.parameters, len(enabled_users) + len(admin))
		
		print("Generating misconfigured permissions on sets - From groups to OUs")
		num_local_admin_groups = sum(len(subarray) for subarray in LOCAL_ADMINS)
		create_misconfig_permissions_on_groups(self.domain, nTiers, self.level, self.parameters, num_local_admin_groups)     

		print("Generating misconfigured membership - Group Nesting")
		create_misconfig_group_nesting(self.domain, nTiers, self.level, self.parameters, num_regular_groups)

		# -------------------------------------------------------------
		#  Generate ACL Permissions, including genericall, genericwrite, writeowner, ....
		print("Creating ACLs permissions")
		create_control_management_permissions(self.domain, nTiers, True, self.parameters, convert_to_digraph)

		# -------------------------------------------------------------
		print("Adding Admin rights")
		assign_administration_to_admin_principals(self.domain, nTiers, convert_to_digraph)
		
		print("Adding Local Admin rights")
		assign_local_admin_rights(self.domain, nTiers, self.parameters, convert_to_digraph) 

		
		# -------------------------------------------------------------
		# Default ACLs
		# Ref: ADSimulator
		create_default_AllExtendedRights(self.domain, nTiers, convert_to_digraph) # Ref: ADSimulator 
		create_default_GenericWrite(self.domain, nTiers, self.parameters, convert_to_digraph) # Ref: ADSimulator
		create_default_owns(self.domain, convert_to_digraph) # Ref: ADSimulator
		create_default_write_dacl_owner(self.domain, nTiers, self.parameters, convert_to_digraph) # Ref: ADSimulator
		create_default_GenericAll(self.domain, nTiers, self.parameters, convert_to_digraph) # Ref: ADSimulator

		
		# -------------------------------------------------------------
		# Kerberoastable users
		print("Creating Kerberoastable users")
		create_kerberoastable_users(nTiers, self.parameters) # O(nUsers * perc of Kerberoastable)
		
		num_nodes = len(NODES)
		num_edges = len(dict_edges)
		print("Num of nodes = ", len(NODES))
		print("Num of edges = ", len(dict_edges))

		try:
			print("Graph density = ", round(num_edges / (num_nodes * (num_nodes - 1)), 5))
		except:
			pass

		for i in NODE_GROUPS:
			print("Number of ", i, " = ", len(NODE_GROUPS[i]))
		
		perc_misconfig_sessions = get_perc_param_value("perc_misconfig_sessions", "Low", self.parameters) / 100
		num_misconfig = int(perc_misconfig_sessions * (len(enabled_users) + len(admin)))
		print(f"Number of regular users = {len(enabled_users) + len(admin)} --- Num misconfig sessions = {num_misconfig}")

		perc_misconfig_permissions = get_perc_param_value("perc_misconfig_permissions", "Low", self.parameters) / 100
		num_misconfig = int(perc_misconfig_permissions * (len(enabled_users) + len(admin)))
		print(f"Number of regular users = {len(enabled_users) + len(admin)} --- Num misconfig permissions = {num_misconfig}")

		print("Dump to JSON file")
		current_datetime = datetime.now()
		# Format the date and time to include seconds
		filename = current_datetime.strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]
		
		with open(f"generated_datasets/{filename}.json", "w") as f:
			for obj in NODES:
				obj["type"] = "node"
				# Use json.dumps() to convert the object to a JSON string without square brackets
				json_str = json.dumps(obj, separators=(',', ':'))
				# Write the JSON string to the file with a newline character
				f.write(json_str + '\n')

		# Open the file in append mode
		with open(f"generated_datasets/{filename}.json", 'a') as f:
			for obj in EDGES:
				# Use json.dumps() to convert the object to a JSON string without square brackets
				obj["type"] = "relationship"  # Added this line for relationships
				json_str = json.dumps(obj, separators=(',', ':'))
				# Write the JSON string to the file with a newline character
				f.write(json_str + '\n')
		
		self.dbname = filename
		# ===============================================
		
		end_ = timer()
		print("Execution time = ", end_ - start_)

		path = f"{os.getcwd()}/generated_datasets/{filename}.json"
		query = f"PROFILE CALL apoc.periodic.iterate(\"CALL apoc.import.json('{path}')\", \"RETURN 1\", {{batchSize:1000}})"
		# session.run(query)
		# session.close()

		print("Database Generation Finished!")


	def generate_data_azure(self): 
		start_ = timer()

		seed_number = get_single_int_param_value("seed", self.parameters)
		if seed_number > 0:
			random.seed(seed_number)

		# Reset database
		reset_DB()

		# Generate tenant
		print(f"Initiating Azure AD tenant - {self.domain}")
		tenant_id = az_create_tenant(self.domain)  # Reuse domain as tenant name

		# ===============================================
		# Create tenant's Azure subscription instance(s)
		print("Creating Azure subscriptions")
		subscriptions = az_create_subscriptions(self.domain, tenant_id, self.parameters)

		# ===============================================
		# Create the roles
		print("Creating roles")
		roles = az_create_roles(tenant_id, self.parameters)

		# ===============================================
		# Create users, including default system users
		print("Creating users")
		users = az_create_users(self.domain, tenant_id, roles, self.first_names, self.last_names, self.parameters)

		# ===============================================
		# Create groups
		print("Creating groups")
		groups = az_create_groups(tenant_id, self.parameters)

		# ===============================================
		# Create management groups
		print("Creating management groups")
		management_groups = az_create_management_groups(tenant_id, subscriptions, self.parameters)

		# ===============================================
		# Create service principals
		print("Creating service principals")
		service_principals = az_create_service_principals(tenant_id, self.parameters)

		# ===============================================
		# Create applications
		print("Creating applications")
		applications = az_create_applications(tenant_id, service_principals, self.parameters)

		# ===============================================
		# Create key vaults
		print("Creating key vaults")
		key_vaults = az_create_key_vaults(tenant_id, subscriptions, self.parameters)

		# ===============================================
		# Create VMs
		print("Creating VMs")
		vms = az_create_vms(tenant_id, subscriptions, self.parameters)

		# ===============================================
		# Assign group memberships
		print("Assigning group memberships")
		az_assign_group_memberships(groups, users, self.parameters)

		# ===============================================
		# Assign roles
		print("Assigning roles")
		az_assign_roles(users, groups, service_principals, roles, tenant_id, subscriptions, self.parameters)

		# ===============================================
		# Generate misconfigured permissions (permission-related edge types)
		print("Generating misconfigured permissions")
		az_create_permissions(users, groups, service_principals, key_vaults, vms, self.parameters)

		# ===============================================
		# Export to JSON
		print("Exporting to JSON file")
		current_datetime = datetime.now()
		filename = current_datetime.strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]
		with open(f"generated_datasets/{filename}.json", "w") as f:
			for obj in NODES:
				obj["type"] = "node"
				json_str = json.dumps(obj, separators=(',', ':'))
				f.write(json_str + '\n')
		with open(f"generated_datasets/{filename}.json", 'a') as f:
			for obj in EDGES:
				json_str = json.dumps(obj, separators=(',', ':'))
				f.write(json_str + '\n')
		self.dbname = filename

		# ===============================================
		# Print statistics
		print("Num of nodes =", len(NODES))
		print("Num of edges =", len(EDGES))
		try:
			print("Graph density =", round(len(EDGES) / (len(NODES) * (len(NODES) - 1)), 5))
		except:
			pass
		for node_type in NODE_GROUPS:
			print(f"Number of {node_type} =", len(NODE_GROUPS[node_type]))

		end_ = timer()
		print("Execution time =", end_ - start_)
		print("Azure AD Database Generation Finished!")


	def write_json(self, session):
		json_path = os.getcwd() + "/" + self.json_file_name
		query = "CALL apoc.export.json.all('" + json_path + "',{useTypes:true})"
		session.run(query)
		print("Graph exported in", json_path)


	# Add these methods to the MainMenu class in ADSynth.py

	def help_generate_hybrid(self):
		print("Generate a hybrid environment with both Azure and on-premises Active Directory in sync")

	def do_generate_hybrid(self, args):
		"""Generate hybrid environment data with Azure and on-premises sync"""
		print("Generating hybrid environment (Azure + On-premises with sync)")
		self.generate_data_hybrid()


	def get_node_index(self, identifier, id_type):
		"""Helper function to get node index by identifier and type"""
		if id_type in DATABASE_ID and identifier in DATABASE_ID[id_type]:
			return DATABASE_ID[id_type][identifier]
		return -1

	def help_generate_hybrid_v2(self):
		print("Generate a complete hybrid AD-Entra identity graph")
		print("Includes: full on-prem AD + multi-tenant seam + NHI nodes")
		print("Paper contribution: per-link SyncIdentity, PHS/PTA/ADFS modes")
	
 
	def do_generate_hybrid_v2(self, args):
		"""
		Full hybrid generation pipeline.
	
		Phase 1: Generate on-prem AD for each domain (reuses existing generate_data())
		Phase 2: Create Entra tenants with posture/orgType metadata
		Phase 3: Create sync links — SyncIdentity + bridge infrastructure
		Phase 4: Create non-human identities (SP, MI, AutomationAccount)
		Phase 5: Create SYNCED_TO user mappings per link
		Phase 6: Validate invariants
		Phase 7: Export
		"""
		import random
		import uuid
		from timeit import default_timer as timer
		from datetime import datetime
		import json
		import os
	
		from adsynth.DATABASE import (
			NODES, EDGES, NODE_GROUPS, dict_edges,
			SYNC_LINKS, SYNC_IDENTITY_NODES, TENANT_METADATA,
			RUN_ID, reset_DB, ridcount,
		)
		import adsynth.DATABASE as DB
	
		start_ = timer()
	
		reset_DB()
		self.generate_data()   # Phase 1: full on-prem AD for domain 0
		seed_val = self.parameters.get("seed", 1)

		# --------------------------------------------------------
		# Build domain list from what generate_data() created
		# --------------------------------------------------------
		domain_nodes = [
			n for n in NODES
			if n["labels"] and n["labels"][-1] == "Domain"
		]
		domains = []
		for n in domain_nodes:
			props = n["properties"]
			domains.append({
				"name":  props.get("name", self.domain),
				"id":    props.get("objectid", self.base_sid),
				"sid":   props.get("objectid", self.base_sid),
			})
	
		if not domains:
			# Fallback if domain node not found by label
			domains = [{
				"name": self.domain,
				"id":   self.base_sid,
				"sid":  self.base_sid,
			}]
	
		# --------------------------------------------------------
		# Phase 2: Create Entra tenants
		# --------------------------------------------------------
		from adsynth.azure_ad_system.az_default_tenants import az_create_tenant
		from adsynth.utils.parameters import get_int_param_value
	
		hybrid_cfg = self.parameters.get("hybrid", {})
		n_tenants = hybrid_cfg.get("nTenants", 3)  # paper default T=3
		posture_dist = hybrid_cfg.get("postureDistribution", {
			"good": 40, "average": 40, "poor": 20
		})
	
		rng_tenant = random.Random(seed_val ^ 0x99)
	
		tenants = []
		for i in range(n_tenants):
			# Build tenant name
			base_name = self.domain.split(".")[0]
			t_name = (
				f"{base_name}.onmicrosoft.com" if i == 0
				else f"{base_name}{i + 1}.onmicrosoft.com"
			)
			org_type = "parent" if i == 0 else "subsidiary"
			posture = rng_tenant.choices(
				list(posture_dist.keys()),
				weights=list(posture_dist.values()),
				k=1
			)[0]
	
			tenant_id = az_create_tenant(t_name)

			TENANT_METADATA[tenant_id] = {
				"orgType": org_type,
				"posture": posture,
			}

			# Update the node properties now that we have the real tenant_id
			t_idx = get_node_index(tenant_id, "objectid")
			if t_idx != -1:
				NODES[t_idx]["properties"]["orgType"] = org_type
				NODES[t_idx]["properties"]["posture"] = posture

			tenants.append({
				"id":   tenant_id,
				"name": t_name,
			})

	
			print(f"  Tenant {i+1}: {t_name} [{org_type}] posture={posture}")
	
		# --------------------------------------------------------
		# Phase 2b: Create Azure roles per tenant
		# (required for Phase 6 NHI role assignments)
		# --------------------------------------------------------
		print("\nPhase 2b: Creating Azure roles per tenant")
		from adsynth.azure_ad_system.az_default_roles import az_create_roles

		roles_per_tenant = {}
		for t in tenants:
			roles = az_create_roles(t["id"], self.parameters)
			roles_per_tenant[t["id"]] = roles
			print(f"  Roles created for {t['name']}: {len(roles)}")

		# --------------------------------------------------------
		# Phase 3: Sync links — SyncIdentity + bridge infrastructure
		# --------------------------------------------------------
		print("\nPhase 3: Creating hybrid seam infrastructure")
		from adsynth.synthesizer.hybrid_seam import create_sync_links
	
		links = create_sync_links(domains, tenants, self.parameters, seed_val)
	
		print(f"  Sync links created: {len(links)}")
		for lnk in links:
			mode = lnk["sync_mode"]
			extras = ""
			if "pta_server_idx" in lnk:
				extras += " +PTA"
			if "adfs_server_idx" in lnk:
				extras += " +ADFS"
			print(f"  {lnk['domain_name']} -> {lnk['tenant_id'][:8]}... [{mode}]{extras}")
	
		# --------------------------------------------------------
		# Phase 4: Non-human identities
		# --------------------------------------------------------
		print("\nPhase 4: Creating non-human identities")
		from adsynth.synthesizer.nhi import create_non_humans
	
		# Count Entra users per tenant for N_generic formula
		users_per_tenant = {}
		for t in tenants:
			count = sum(
				1 for n in NODES
				if n["labels"] and n["labels"][-1] == "AZUser"
				and n["properties"].get("tenantid") == t["id"]
			)
			users_per_tenant[t["id"]] = count if count > 0 else (
				self.parameters.get("AZUser", {}).get("nUsers", 50)
			)
	
		nhi_result = create_non_humans(
			domains, tenants, users_per_tenant, self.parameters, seed_val
		)
	
		total_nhi = (
			sum(len(v) for v in nhi_result["sp_by_tenant"].values())
			+ sum(len(v) for v in nhi_result["mi_by_tenant"].values())
			+ sum(len(v) for v in nhi_result["aa_by_domain"].values())
			+ len(nhi_result["cross_pool"])
		)
		print(f"  Total NHI nodes created: {total_nhi}")
		print(f"  AI Agent nodes: {len(nhi_result['ai_agents'])}")
		print(f"  Cross-tenant pool: {len(nhi_result['cross_pool'])}")
		print(f"  ORCHESTRATES edges: {nhi_result['orchestrates_edges']}")
		print(f"  DELEGATES_TO edges: {nhi_result['delegates_to_edges']}")
		print(f"  HAS_TOOL_ACCESS edges: {nhi_result['tool_access_edges']}")
	
		# --------------------------------------------------------
		# Phase 5: SYNCED_TO user mappings
		# --------------------------------------------------------
		print("\nPhase 5: Creating SYNCED_TO user mappings")
		from adsynth.synthesizer.hybrid_seam import create_user_synced_to_edges
	
		rng_sync = random.Random(seed_val ^ 0xC0FFEE)
		total_synced = 0
		for lnk in links:
			n = create_user_synced_to_edges(
				lnk["domain_name"],
				lnk["tenant_id"],
				self.parameters,
				rng_sync,
			)
			total_synced += n
		print(f"  SYNCED_TO edges created: {total_synced}")
		# Now delegation edges can fire because AZUser nodes exist
		from adsynth.synthesizer.nhi import create_delegation_edges
		rng_deleg = random.Random(seed_val ^ 0xDE16)
		deleg_edges = create_delegation_edges(nhi_result["sp_by_tenant"], rng_deleg)
		print(f"  DELEGATES_TO edges created: {deleg_edges}")
			
		
		# --------------------------------------------------------
		# Phase 6: Permissions and misconfiguration injection
		# --------------------------------------------------------

		print("\nPhase 6: Permissions and misconfiguration injection")

		perm_summary = run_hybrid_permissions_phase(
			domains=domains,
			tenants=tenants,
			config=self.parameters,
			seed=seed_val,
		)
		print(f"  Total NHI role edges:                {perm_summary['nhi_role_edges']}")
		print(f"  SyncIdentity domain rights:          {perm_summary['sync_right_edges']}")
		print(f"  AutomationAccount delegated rights:  {perm_summary['deleg_edges']}")
		print(f"  AI Agent permission edges:           {perm_summary['ai_perm_edges']}")
		print(f"  Misconfig edges injected:            {perm_summary['total_misconfig']}")
		for mtype, count in perm_summary['misconfig_counts'].items():
			print(f"    {mtype}: {count}")

		# --------------------------------------------------------
		# Phase 7: Invariant validation
		# --------------------------------------------------------
		
		print("\nPhase 6: Validating semantic invariants")
		from adsynth.hybrid_system.invariant_validators import (
			validate_graph_invariants, print_validation_report
		)
		results = validate_graph_invariants()
		print_validation_report(results)
	
		# --------------------------------------------------------
		# Phase 8: Export
		# --------------------------------------------------------
		print("\nPhase 7: Exporting to JSON")
	
		num_nodes = len(NODES)
		num_edges = len(dict_edges)
		print(f"  Total nodes: {num_nodes}")
		print(f"  Total edges: {num_edges}")
	
		try:
			print(f"  Graph density: {round(num_edges / (num_nodes * (num_nodes - 1)), 5)}")
		except:
			pass
	
		for label in NODE_GROUPS:
			if NODE_GROUPS[label]:
				count = len(NODE_GROUPS[label])
				# For AIAgent, annotate it is a subset of AZServicePrincipal
				if label == "AIAgent":
					print(f"  AIAgent (subset of AZServicePrincipal): {count}")
				else:
					print(f"  {label}: {count}")
	
		current_datetime = datetime.now()
		filename = "hybrid_v2_" + current_datetime.strftime("%Y-%m-%d_%H-%M-%S-%f")[:-3]
	
		os.makedirs("generated_datasets", exist_ok=True)
	
		with open(f"generated_datasets/{filename}.json", "w") as f:
			for obj in NODES:
				obj["type"] = "node"
				json_str = json.dumps(obj, separators=(",", ":"))
				f.write(json_str + "\n")
	
		with open(f"generated_datasets/{filename}.json", "a") as f:
			for obj in EDGES:
				obj["type"] = "relationship"
				json_str = json.dumps(obj, separators=(",", ":"))
				f.write(json_str + "\n")
	
		self.dbname = filename
	
		end_ = timer()
		print(f"\nHybrid v2 generation complete in {end_ - start_:.2f}s")
		print(f"Output: generated_datasets/{filename}.json")
		print(f"  Permission edges (NHI roles): {perm_summary['nhi_role_edges']}")
		print(f"  Misconfig edges:              {perm_summary['total_misconfig']}")
  
	    # --------------------------------------------------------
		# Phase 8: Seam metrics (Week 8)
		# --------------------------------------------------------
		print("\\nPhase 8: Computing seam metrics")
		from adsynth.hybrid_system.seam_metrics import (
			compute_seam_metrics, print_seam_metrics_report, export_metrics_json
		)
 
		seam_metrics = compute_seam_metrics(domains, tenants)
		print_seam_metrics_report(seam_metrics)
	
		metrics_path = export_metrics_json(seam_metrics)
		print(f"  Metrics JSON: {metrics_path}")
	
	def edge_operation(self, source_idx, target_idx, edge_type, prop_names=None, prop_values=None):
		"""Helper function to create edges with properties"""
		if source_idx == -1 or target_idx == -1:
			return
			
		edge = {
			"id": str(len(EDGES)),
			"type": "relationship",
			"label": edge_type,
			"start": {"id": str(source_idx)},
			"end": {"id": str(target_idx)},
			"properties": {}
		}
		
		if prop_names and prop_values and len(prop_names) == len(prop_values):
			for name, value in zip(prop_names, prop_values):
				edge["properties"][name] = value
		
		EDGES.append(edge)
		
		# Update dict_edges for tracking
		edge_key = f"{source_idx}-{target_idx}-{edge_type}"
		if edge_key not in dict_edges:
			dict_edges[edge_key] = 1

	# Additionally, you need to modify the generate_data_hybrid method slightly:
	# Replace the Azure tenant creation section with this:

	def generate_data_hybrid(self):
		"""Generate a comprehensive hybrid environment with both on-premises and Azure components"""
		start_ = timer()
		
		# Set seed for reproducibility
		seed_number = get_single_int_param_value("seed", self.parameters)
		if seed_number > 0:
			random.seed(seed_number)

		# Reset database
		reset_DB()
		
		# Initialize Azure node groups first
		azure_node_types = ["AZUser", "AZGroup", "AZTenant", "AZSubscription", 
						"AZRole", "AZServicePrincipal", "AZApp", "AZManagementGroup", 
						"AZKeyVault", "AZVM"]
		for node_type in azure_node_types:
			if node_type not in NODE_GROUPS:
				NODE_GROUPS[node_type] = []
		
		print("=== PHASE 1: Generating On-Premises Active Directory ===")
		
		# Generate on-premises AD (comprehensive version)
		domain_dn = get_domain_dn(self.domain)
		nTiers = get_num_tiers(self.parameters)
		ridcount.extend([1000])
		
		# Create domain and basic structure
		print(f"Creating on-premises domain - {self.domain}")
		functional_level = create_domain(self.domain, self.base_sid, domain_dn, self.parameters)
		create_ad_skeleton(self.domain, self.base_sid, self.parameters, nTiers)
		
		# Create comprehensive on-premises structure
		create_default_groups(self.domain, self.base_sid, self.old_domain)
		create_admin_groups(self.domain, self.base_sid, nTiers)
		
		# Create GPOs and OUs
		ddp = cs(str(uuid.uuid4()), self.base_sid).upper()
		ddcp = cs(str(uuid.uuid4()), self.base_sid).upper()
		dcou = cs(str(uuid.uuid4()), self.base_sid).upper()
		gpos_container = cs(str(uuid.uuid4()), self.base_sid).upper()
		
		create_gpos_container(self.domain, domain_dn, gpos_container)
		create_default_gpos(self.domain, domain_dn, ddp, ddcp)
		create_domain_controllers_ou(self.domain, domain_dn, dcou)
		apply_default_gpos(self.domain, ddp, ddcp, dcou)
		
		# Create ACLs
		create_enterprise_admins_acls(self.domain)
		create_administrators_acls(self.domain)
		create_domain_admins_acls(self.domain)
		create_default_dc_groups_acls(self.domain)
		
		# Generate Domain Controllers
		dc_properties_list, domain_controllers = generate_dcs(self.domain, self.base_sid, 
															domain_dn, dcou, self.current_time, 
															self.parameters, functional_level)
		
		# Apply GPOs to tiers
		apply_gpos(self.domain, self.base_sid, nTiers)
		apply_restriction_gpos(self.domain, self.base_sid, self.parameters)
		place_gpos_in_container(self.domain, gpos_container)
		
		# Generate default users
		generate_guest_user(self.domain, self.base_sid, self.parameters)
		generate_default_account(self.domain, self.base_sid, self.parameters)
		generate_administrator(self.domain, self.base_sid, self.parameters)
		generate_krbtgt_user(self.domain, self.base_sid, self.parameters)
		link_default_users_to_domain(self.domain, self.base_sid)
		
		create_default_users_acls(self.domain, self.base_sid)
		create_adminstrator_memberships(self.domain)
		generate_default_member_of(self.domain, self.base_sid, self.old_domain)
		create_default_groups_acls(self.domain, self.base_sid)
		
		# Generate regular users
		num_users = get_int_param_value("User", "nUsers", self.parameters)
		print(f"Creating {num_users} on-premises users")
		onprem_users, onprem_disabled = generate_users(self.domain, self.base_sid, num_users, 
													self.current_time, self.first_names, 
													self.last_names, self.parameters)
		
		# Segregate admin and regular users
		perc_admin = get_perc_param_value("Admin", "Admin_Percentage", self.parameters)
		all_admins, all_enabled_users = segregate_list(onprem_users, [perc_admin, 100 - perc_admin])
		
		misconfig_admin_regular_perc = get_perc_param_value("nodeMisconfig", "admin_regular", self.parameters)
		if misconfig_admin_regular_perc > 50:
			misconfig_admin_regular_perc = DEFAULT_CONFIGURATIONS["nodeMisconfig"]["admin_regular"]
		admin, misconfig_admin = segregate_list(all_admins, [100 - misconfig_admin_regular_perc, misconfig_admin_regular_perc])
		
		misconfig_user_comp_perc = get_perc_param_value("nodeMisconfig", "user_comp", self.parameters)
		if misconfig_admin_regular_perc + misconfig_user_comp_perc > 50:
			misconfig_admin_regular_perc = DEFAULT_CONFIGURATIONS["nodeMisconfig"]["admin_regular"]
			misconfig_user_comp_perc = DEFAULT_CONFIGURATIONS["nodeMisconfig"]["user_comp"]
		enabled_users, misconfig_regular_users, misconfig_users_comps = \
			segregate_list(all_enabled_users, [100 - misconfig_admin_regular_perc - misconfig_user_comp_perc, 
											misconfig_admin_regular_perc, misconfig_user_comp_perc])
		
		# Generate computers
		num_computers = get_int_param_value("Computer", "nComputers", self.parameters)
		print(f"Creating {num_computers} on-premises computers")
		computers, PAW, Servers, Workstations = generate_computers(self.domain, self.base_sid, 
																num_computers, [], self.current_time, 
																self.parameters)
		
		Workstations, misconfig_workstations = segregate_list(Workstations, [100 - misconfig_user_comp_perc, misconfig_user_comp_perc])
		place_computers_in_tiers(self.domain, self.base_sid, nTiers, self.parameters, PAW, Servers, Workstations, misconfig_users_comps)
		
		# Place users in tiers
		server_operators = []
		print_operators = []
		place_admin_users_in_tiers(self.domain, self.base_sid, nTiers, admin, misconfig_regular_users, 
								server_operators, print_operators, self.parameters)
		place_normal_users_in_tiers(self.domain, enabled_users, onprem_disabled, misconfig_admin, 
								misconfig_workstations, nTiers)
		
		# Create groups and relationships
		num_regular_groups = create_groups(self.domain, self.base_sid, self.parameters, nTiers)
		nest_groups(self.domain, self.parameters)
		it_users = place_users_in_groups(self.domain, nTiers, self.parameters)
		
		# Create sessions
		create_sessions(nTiers, PAW_TIERS, S_TIERS, WS_TIERS, self.parameters)
		create_misconfig_sessions(nTiers, self.level, self.parameters, len(enabled_users) + len(admin))
		create_dc_sessions(domain_controllers, server_operators, print_operators)
		
		print("=== PHASE 2: Generating Comprehensive Azure Active Directory ===")
		
		# Create Azure tenant - FIXED VERSION
		print(f"Creating Azure tenant for domain - {self.domain}")
		tenant_id = str(uuid.uuid4()).upper()
		tenant_node = {
			"id": str(len(NODES)),
			"labels": ["AZTenant"],
			"properties": {
				"name": self.domain,
				"objectid": tenant_id,
				"displayName": self.domain,
				"tenantid": tenant_id
			}
		}
		
		# Add tenant to database manually to ensure it's tracked
		tenant_idx = len(NODES)
		NODES.append(tenant_node)
		NODE_GROUPS["AZTenant"].append(tenant_idx)
		DATABASE_ID["objectid"][tenant_id] = tenant_idx
		
		# Create comprehensive Azure infrastructure
		print("Creating Azure subscriptions")
		subscriptions = az_create_subscriptions(self.domain, tenant_id, self.parameters)
		
		print("Creating Azure roles") 
		roles = az_create_roles(tenant_id, self.parameters)
		
		print("Creating Azure management groups")
		management_groups = az_create_management_groups(tenant_id, subscriptions, self.parameters)
		
		print("Creating Azure service principals")
		service_principals = az_create_service_principals(tenant_id, self.parameters)
		
		print("Creating Azure applications")
		applications = az_create_applications(tenant_id, service_principals, self.parameters)
		
		print("Creating Azure key vaults")
		key_vaults = az_create_key_vaults(tenant_id, subscriptions, self.parameters)
		
		print("Creating Azure VMs")
		vms = az_create_vms(tenant_id, subscriptions, self.parameters)
		
		print("Creating Azure groups")
		azure_groups = az_create_groups(tenant_id, self.parameters)
		
		print("=== PHASE 3: Creating Synced Azure Users ===")
		
		# Create Azure users that are synced from on-premises
		azure_users = self.create_synced_azure_users(onprem_users, tenant_id, roles)
		
		# Add some cloud-only Azure users
		cloud_only_users = self.create_cloud_only_azure_users(tenant_id, roles)
		all_azure_users = azure_users + cloud_only_users
		
		# Replace the Phase 4 section in your generate_data_hybrid method with this:

		print("=== PHASE 4: Creating Azure Relationships ===")

		# Convert user indices to object IDs for Azure functions
		azure_user_ids = []
		for user_idx in all_azure_users:
			if user_idx < len(NODES):
				node = NODES[user_idx]
				if "objectid" in node["properties"]:
					azure_user_ids.append(node["properties"]["objectid"])

		# Assign group memberships
		print("Assigning Azure group memberships")
		if azure_groups and azure_user_ids:
			try:
				az_assign_group_memberships(azure_groups, azure_user_ids, self.parameters)
			except Exception as e:
				print(f"Warning: Error in group membership assignment: {e}")
				print("Continuing with hybrid generation...")

		# Assign roles
		print("Assigning Azure roles")
		if roles and azure_user_ids:
			try:
				az_assign_roles(azure_user_ids, azure_groups, service_principals, roles, 
							tenant_id, subscriptions, self.parameters)
			except Exception as e:
				print(f"Warning: Error in role assignment: {e}")
				print("Continuing with hybrid generation...")

		# Generate Azure permissions
		print("Generating Azure permissions")
		if azure_user_ids:
			try:
				az_create_permissions(azure_user_ids, azure_groups, service_principals, 
									key_vaults, vms, self.parameters)
			except Exception as e:
				print(f"Warning: Error in permission creation: {e}")
				print("Continuing with hybrid generation...")
		
		print("=== PHASE 5: Creating Sync Relationships ===")
		
		# Create sync relationships between on-premises and Azure
		self.create_sync_relationships(onprem_users[:len(azure_users)], azure_users)
		
		# Add hybrid-specific relationships
		self.create_comprehensive_hybrid_relationships(onprem_users, all_azure_users, azure_groups, 
													service_principals, key_vaults, vms)
		
		print("=== PHASE 6: Finalizing On-Premises Permissions ===")
		
		# Complete on-premises permissions and ACLs
		convert_to_digraph = get_single_int_param_value("convert_to_directed_graphs", self.parameters)
		
		create_control_management_permissions(self.domain, nTiers, False, self.parameters, convert_to_digraph)
		create_misconfig_permissions_on_individuals(nTiers, ADMIN_USERS, ENABLED_USERS, 
												self.level, self.parameters, len(enabled_users) + len(admin))
		
		num_local_admin_groups = sum(len(subarray) for subarray in LOCAL_ADMINS)
		create_misconfig_permissions_on_groups(self.domain, nTiers, self.level, 
											self.parameters, num_local_admin_groups)
		create_misconfig_group_nesting(self.domain, nTiers, self.level, self.parameters, num_regular_groups)
		
		# Create ACL permissions
		create_control_management_permissions(self.domain, nTiers, True, self.parameters, convert_to_digraph)
		assign_administration_to_admin_principals(self.domain, nTiers, convert_to_digraph)
		assign_local_admin_rights(self.domain, nTiers, self.parameters, convert_to_digraph)
		
		# Default ACLs
		create_default_AllExtendedRights(self.domain, nTiers, convert_to_digraph)
		create_default_GenericWrite(self.domain, nTiers, self.parameters, convert_to_digraph)
		create_default_owns(self.domain, convert_to_digraph)
		create_default_write_dacl_owner(self.domain, nTiers, self.parameters, convert_to_digraph)
		create_default_GenericAll(self.domain, nTiers, self.parameters, convert_to_digraph)
		
		# Kerberoastable users
		create_kerberoastable_users(nTiers, self.parameters)
		
		print("=== PHASE 7: Export and Statistics ===")
		
		# Export to JSON
		current_datetime = datetime.now()
		filename = f"hybrid_{current_datetime.strftime('%Y-%m-%d_%H-%M-%S-%f')[:-3]}"
		
		with open(f"generated_datasets/{filename}.json", "w") as f:
			for obj in NODES:
				obj["type"] = "node"
				json_str = json.dumps(obj, separators=(',', ':'))
				f.write(json_str + '\n')
		
		with open(f"generated_datasets/{filename}.json", 'a') as f:
			for obj in EDGES:
				obj["type"] = "relationship"
				json_str = json.dumps(obj, separators=(',', ':'))
				f.write(json_str + '\n')
		
		self.dbname = filename
		
		# Print comprehensive statistics
		print("=== COMPREHENSIVE HYBRID ENVIRONMENT STATISTICS ===")
		print(f"Total nodes: {len(NODES)}")
		print(f"Total edges: {len(EDGES)}")
		print(f"Sync relationships: {len(SYNC_RELATIONSHIPS)}")
		print(f"Hybrid objects: {len(HYBRID_OBJECTS)}")
		
		try:
			print(f"Graph density: {round(len(EDGES) / (len(NODES) * (len(NODES) - 1)), 5)}")
		except:
			pass
		
		# Detailed node type statistics
		print("\n--- Node Type Breakdown ---")
		for node_type in sorted(NODE_GROUPS.keys()):
			if NODE_GROUPS[node_type]:
				print(f"Number of {node_type}: {len(NODE_GROUPS[node_type])}")
		
		# On-premises vs Azure statistics
		onprem_types = ["User", "Computer", "Group", "Domain", "OU", "GPO"]
		azure_types = ["AZUser", "AZGroup", "AZTenant", "AZSubscription", "AZRole", 
					"AZServicePrincipal", "AZApp", "AZManagementGroup", "AZKeyVault", "AZVM"]
		
		onprem_count = sum(len(NODE_GROUPS.get(t, [])) for t in onprem_types)
		azure_count = sum(len(NODE_GROUPS.get(t, [])) for t in azure_types)
		
		print(f"\n--- Environment Breakdown ---")
		print(f"On-premises objects: {onprem_count}")
		print(f"Azure objects: {azure_count}")
		print(f"Sync ratio: {len(SYNC_RELATIONSHIPS)}/{len(onprem_users)} ({round(len(SYNC_RELATIONSHIPS)/len(onprem_users)*100, 1)}%)")
		
		end_ = timer()
		print(f"\nHybrid environment generation completed in {end_ - start_:.2f} seconds")

	def create_synced_azure_users(self, onprem_users, tenant_id, roles):
		"""Create Azure users that are synced from on-premises"""
		# Sync 70% of on-premises users to Azure (configurable)
		sync_percentage = 70
		num_synced = int(len(onprem_users) * sync_percentage / 100)
		
		synced_onprem_users = random.sample(onprem_users, num_synced)
		azure_users = []
		
		print(f"Syncing {num_synced} users from on-premises to Azure")
		
		for onprem_user in synced_onprem_users:
			# Extract user info from on-premises user
			onprem_node_idx = self.get_node_index(onprem_user + "_User", "name")
			if onprem_node_idx == -1:
				continue
				
			onprem_node = NODES[onprem_node_idx]
			
			# Create corresponding Azure user
			azure_user_id = str(uuid.uuid4()).upper()
			display_name = onprem_node["properties"].get("displayname", "Unknown User")
			
			# Create UPN based on on-premises name
			base_name = onprem_user.split("@")[0] if "@" in onprem_user else onprem_user
			upn = f"{base_name.lower()}@{self.domain.lower()}"
			
			# Create Azure user node manually - FIXED to match expected format
			azure_node = {
				"id": str(len(NODES)),
				"labels": ["AZUser"],
				"properties": {
					"name": display_name,  # This is what az_assign_roles looks for
					"userPrincipalName": upn,
					"objectid": azure_user_id,
					"tenantid": tenant_id,
					"enabled": onprem_node["properties"].get("enabled", True),
					"displayName": display_name,
					"syncedFromOnPremises": True,
					"onPremisesUserPrincipalName": onprem_user
				}
			}
			
			# Add to NODES and update tracking
			azure_node_idx = len(NODES)
			NODES.append(azure_node)
			NODE_GROUPS["AZUser"].append(azure_node_idx)
			DATABASE_ID["objectid"][azure_user_id] = azure_node_idx
			
			# Create tenant relationship - check if tenant exists first
			tenant_idx = self.get_node_index(tenant_id, "objectid")
			if tenant_idx != -1:
				self.edge_operation(tenant_idx, azure_node_idx, "AZContains")
			else:
				print(f"Warning: Tenant {tenant_id} not found, skipping tenant relationship")
			
			# IMPORTANT: Store the node INDEX, not the ID for compatibility with Azure functions
			azure_users.append(azure_node_idx)
			
			# Store sync relationship using the original user identifier
			SYNC_RELATIONSHIPS[onprem_user] = azure_user_id
			HYBRID_OBJECTS[onprem_user] = {
				"onprem_id": onprem_user,
				"azure_id": azure_user_id,
				"azure_idx": azure_node_idx,
				"type": "User"
			}
		
		return azure_users

	def create_cloud_only_azure_users(self, tenant_id, roles):
		"""Create Azure-only users that don't exist on-premises"""
		# Create some cloud-only users (contractors, external partners, etc.)
		cloud_user_count = max(10, int(get_int_param_value("User", "nUsers", self.parameters) * 0.15))
		cloud_users = []
		
		print(f"Creating {cloud_user_count} cloud-only Azure users")
		
		for i in range(cloud_user_count):
			first_name = random.choice(self.first_names)
			last_name = random.choice(self.last_names)
			display_name = f"{first_name} {last_name}"
			upn = f"{first_name.lower()}.{last_name.lower()}@{self.domain.lower()}"
			
			user_id = str(uuid.uuid4()).upper()
			
			# FIXED to match expected format
			user_node = {
				"id": str(len(NODES)),
				"labels": ["AZUser"],
				"properties": {
					"name": display_name,  # This is what az_assign_roles looks for
					"userPrincipalName": upn,
					"objectid": user_id,
					"tenantid": tenant_id,
					"enabled": random.choice([True, True, True, False]),  # 75% enabled
					"displayName": display_name,
					"syncedFromOnPremises": False,
					"userType": random.choice(["Member", "Guest"]),
					"accountType": "Cloud-Only"
				}
			}
			
			user_idx = len(NODES)
			NODES.append(user_node)
			NODE_GROUPS["AZUser"].append(user_idx)
			DATABASE_ID["objectid"][user_id] = user_idx
			
			# Create tenant relationship
			tenant_idx = self.get_node_index(tenant_id, "objectid")
			if tenant_idx != -1:
				self.edge_operation(tenant_idx, user_idx, "AZContains")
			
			# IMPORTANT: Store the node INDEX, not the ID for compatibility with Azure functions
			cloud_users.append(user_idx)
			CLOUD_ONLY_OBJECTS[user_id] = {
				"type": "User", 
				"created_in": "Azure",
				"azure_idx": user_idx
			}
		
		return cloud_users

	def create_sync_relationships(self, onprem_users, azure_user_indices):
		"""Create explicit sync relationships between on-premises and Azure objects"""
		print("Creating sync relationships between on-premises and Azure")
		
		synced_count = 0
		for onprem_user in onprem_users:
			if onprem_user in SYNC_RELATIONSHIPS:
				azure_user_id = SYNC_RELATIONSHIPS[onprem_user]
				
				# Find the actual node indices
				onprem_idx = self.get_node_index(onprem_user + "_User", "name")
				azure_idx = self.get_node_index(azure_user_id, "objectid")
				
				if onprem_idx != -1 and azure_idx != -1:
					# Create bidirectional sync relationship using edge_operation
					self.edge_operation(onprem_idx, azure_idx, "SyncedTo", 
								["syncType", "syncDirection"], 
								["AADConnect", "OnPremToAzure"])
					
					self.edge_operation(azure_idx, onprem_idx, "SyncedFrom", 
								["syncType", "syncDirection"], 
								["AADConnect", "AzureToOnPrem"])
					synced_count += 1
		
		print(f"Created {synced_count} sync relationships")

	def create_comprehensive_hybrid_relationships(self, onprem_users, azure_user_indices, azure_groups, 
											 service_principals, key_vaults, vms):
		"""Create comprehensive hybrid-specific relationships and cross-environment permissions"""
		print("Creating comprehensive hybrid relationships")
		
		if not azure_user_indices:
			print("No Azure users available, skipping hybrid relationships")
			return
		
		# Convert indices back to object IDs for some operations
		azure_user_ids = []
		for idx in azure_user_indices:
			if idx < len(NODES):
				node = NODES[idx]
				if "objectid" in node["properties"]:
					azure_user_ids.append(node["properties"]["objectid"])
		
		# 1. Azure users managing on-premises resources
		num_hybrid_admins = min(8, len(azure_user_indices))
		if num_hybrid_admins > 0:
			hybrid_admin_indices = random.sample(azure_user_indices, num_hybrid_admins)
			
			for admin_idx in hybrid_admin_indices:
				if admin_idx >= len(NODES):
					continue
					
				# Azure admin can reset on-premises user passwords
				if onprem_users:
					target_onprem = random.choice(onprem_users)
					target_idx = self.get_node_index(target_onprem + "_User", "name")
					if target_idx != -1:
						self.edge_operation(admin_idx, target_idx, "ForceChangePassword",
									["isHybridPermission", "grantedVia"],
									[True, "Azure AD Privileged Identity Management"])
				
				# Azure admin can manage on-premises computers
				if COMPUTERS:
					target_computer = random.choice(COMPUTERS)
					comp_idx = self.get_node_index(target_computer, "name")
					if comp_idx != -1:
						self.edge_operation(admin_idx, comp_idx, "AdminTo",
									["isHybridPermission", "grantedVia"],
									[True, "Azure Arc"])
		
		# 2. Service principals accessing on-premises resources
		if service_principals:
			num_sp_onprem_access = min(3, len(service_principals))
			sp_with_onprem_access = random.sample(service_principals, num_sp_onprem_access)
			
			for sp_id in sp_with_onprem_access:
				sp_idx = self.get_node_index(sp_id, "objectid")
				if sp_idx == -1:
					continue
					
				# Service principal can read from on-premises
				if ENABLED_USERS:
					target_user = random.choice(ENABLED_USERS)
					user_idx = self.get_node_index(target_user + "_User", "name")
					if user_idx != -1:
						self.edge_operation(sp_idx, user_idx, "ReadLAPSPassword",
									["isHybridPermission", "grantedVia"],
									[True, "Hybrid Identity"])
		
		# 3. On-premises users with Azure permissions
		num_onprem_azure_access = min(15, len(onprem_users))
		if num_onprem_azure_access > 0:
			onprem_azure_users = random.sample(onprem_users, num_onprem_azure_access)
			
			for onprem_user in onprem_azure_users:
				if onprem_user in SYNC_RELATIONSHIPS:
					azure_counterpart_id = SYNC_RELATIONSHIPS[onprem_user]
					azure_idx = self.get_node_index(azure_counterpart_id, "objectid")
					if azure_idx == -1:
						continue
					
					# Azure group membership
					if azure_groups:
						target_group = random.choice(azure_groups)
						group_idx = self.get_node_index(target_group, "objectid")
						if group_idx != -1:
							self.edge_operation(azure_idx, group_idx, "AZMemberOf",
										["grantedViaSync"], [True])
					
					# Azure resource permissions
					if key_vaults and random.random() < 0.3:  # 30% chance
						target_kv = random.choice(key_vaults)
						kv_idx = self.get_node_index(target_kv, "objectid")
						if kv_idx != -1:
							self.edge_operation(azure_idx, kv_idx, "AZKeyVaultContributor",
										["grantedViaSync", "source"], 
										[True, "On-premises group membership"])
					
					if vms and random.random() < 0.2:  # 20% chance
						target_vm = random.choice(vms)
						vm_idx = self.get_node_index(target_vm, "objectid")
						if vm_idx != -1:
							self.edge_operation(azure_idx, vm_idx, "AZVMContributor",
										["grantedViaSync", "source"],
										[True, "On-premises admin rights"])
		
		# 4. Cross-environment group relationships - FIXED
		if azure_groups:
			# Get all on-premises security groups (flatten SECURITY_GROUPS if it contains lists)
			onprem_security_groups = []
			try:
				# SECURITY_GROUPS might be a list of lists or a simple list
				if SECURITY_GROUPS:
					if isinstance(SECURITY_GROUPS[0], list):
						# If it's a list of lists, flatten it
						for group_list in SECURITY_GROUPS:
							onprem_security_groups.extend(group_list)
					else:
						# If it's a simple list, use it directly
						onprem_security_groups = SECURITY_GROUPS
			except (IndexError, TypeError):
				# If SECURITY_GROUPS is empty or malformed, skip this section
				print("Warning: SECURITY_GROUPS is empty or malformed, skipping group correspondence")
				onprem_security_groups = []
			
			if onprem_security_groups:
				# Some Azure groups correspond to on-premises groups
				num_corresponding_groups = min(len(azure_groups), len(onprem_security_groups), 5)
				
				for i in range(num_corresponding_groups):
					if i < len(azure_groups) and i < len(onprem_security_groups):
						azure_group_id = azure_groups[i]
						onprem_group = onprem_security_groups[i]
						
						# Ensure onprem_group is a string, not a list
						if isinstance(onprem_group, (list, tuple)):
							if onprem_group:  # If the list is not empty
								onprem_group = onprem_group[0]  # Take the first element
							else:
								continue  # Skip empty lists
						
						azure_group_idx = self.get_node_index(azure_group_id, "objectid")
						onprem_group_idx = self.get_node_index(onprem_group, "name")
						
						if azure_group_idx != -1 and onprem_group_idx != -1:
							# Create correspondence relationship
							self.edge_operation(onprem_group_idx, azure_group_idx, "SyncedTo",
										["syncType", "groupCorrespondence"],
										["AADConnect", True])
							self.edge_operation(azure_group_idx, onprem_group_idx, "SyncedFrom",
										["syncType", "groupCorrespondence"],
										["AADConnect", True])
		
		# 5. Conditional Access and Intune relationships
		if vms and COMPUTERS:
			# Some on-premises computers are Azure AD joined or hybrid joined
			num_hybrid_joined = min(len(COMPUTERS), int(len(COMPUTERS) * 0.4))  # 40% hybrid joined
			hybrid_joined_computers = random.sample(COMPUTERS, num_hybrid_joined)
			
			for computer in hybrid_joined_computers:
				comp_idx = self.get_node_index(computer, "name")
				if comp_idx == -1:
					continue
					
				# Computer has relationship to Azure
				if vms:
					target_vm = random.choice(vms)
					vm_idx = self.get_node_index(target_vm, "objectid")
					if vm_idx != -1:
						self.edge_operation(comp_idx, vm_idx, "AzureADJoined",
									["joinType", "managedBy"],
									["Hybrid", "Intune"])

		print(f"Created hybrid relationships: {len(azure_user_indices)} Azure users, {len(onprem_users)} on-premises users")
	def generate_data_hybrid_phase4_fixed(self, all_azure_users, azure_groups, service_principals, roles, tenant_id, subscriptions, key_vaults, vms):
		"""Fixed Phase 4: Creating Azure Relationships"""
		print("=== PHASE 4: Creating Azure Relationships ===")
		
		# Assign group memberships - use indices directly
		print("Assigning Azure group memberships")
		if azure_groups and all_azure_users:
			# Convert user indices to the format expected by az_assign_group_memberships
			# The Azure functions expect user IDs, not indices
			azure_user_ids = []
			for user_idx in all_azure_users:
				if user_idx < len(NODES):
					node = NODES[user_idx]
					if "objectid" in node["properties"]:
						azure_user_ids.append(node["properties"]["objectid"])
			
			if azure_user_ids:
				az_assign_group_memberships(azure_groups, azure_user_ids, self.parameters)
		
		# Assign roles - use indices directly
		print("Assigning Azure roles")
		if roles and all_azure_users:
			# Convert user indices to the format expected by az_assign_roles
			azure_user_ids = []
			for user_idx in all_azure_users:
				if user_idx < len(NODES):
					node = NODES[user_idx]
					if "objectid" in node["properties"]:
						azure_user_ids.append(node["properties"]["objectid"])
			
			if azure_user_ids:
				try:
					az_assign_roles(azure_user_ids, azure_groups, service_principals, roles, 
								tenant_id, subscriptions, self.parameters)
				except Exception as e:
					print(f"Warning: Error in role assignment: {e}")
					print("Continuing with hybrid generation...")
		
		# Generate Azure permissions
		print("Generating Azure permissions")
		if all_azure_users:
			azure_user_ids = []
			for user_idx in all_azure_users:
				if user_idx < len(NODES):
					node = NODES[user_idx]
					if "objectid" in node["properties"]:
						azure_user_ids.append(node["properties"]["objectid"])
			
			if azure_user_ids:
				try:
					az_create_permissions(azure_user_ids, azure_groups, service_principals, 
										key_vaults, vms, self.parameters)
				except Exception as e:
					print(f"Warning: Error in permission creation: {e}")
					print("Continuing with hybrid generation...")