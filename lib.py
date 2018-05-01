from datetime import date

def verify_date(datestr):
    try:
        date_arr = [int(i) for i in datestr.split('-')]
        date(date_arr[0],date_arr[1],date_arr[2])
        return datestr
    except ValueError:
        return ""

def parse_majcom(majcom):
	majlow = majcom.lower()
	if "air combat" in majlow:
		return "ACC"
	elif "education" in majlow:
		return "AETC"
	elif "global strike" in majlow:
		return "AFGSC"
	elif "materiel" in majlow:
		return "AFMC"
	elif "reserve" in majlow:
		return "AFRC"
	elif "space" in majlow:
		return "AFSC"
	elif "special" in majlow:
		return "AFSOC"
	elif "mobility" in majlow:
		return "AMC"
	elif "pacific" in majlow:
		return "PACAF"
	elif "europe" in majlow:
		return "USAFE"
	else:
		return ""

def extend_majcom(majcom):
	if majcom == "ACC":
		return "Air Combat Command"
	elif majcom == "AETC":
		return "Air Education and Training Command"
	elif majcom == "AFGSC":
		return "AF Global Strike Command"
	elif majcom == "AFMC":
		return "AF Materiel Command"
	elif majcom == "AFRC":
		return "AF Reserve Command"
	elif majcom == "AFSC":
		return "AF Space Command"
	elif majcom == "AFSOC":
		return "AF Special Operations Command"
	elif majcom == "AMC":
		return "Air Mobility Command"
	elif majcom == "PACAF":
		return "Pacific Air Forces"
	elif majcom == "USAFE":
		return "USAF in Europe"
	else:
		return ""

def parse_branch(branch):
	branchlow = branch.lower()
	if "air force" in branchlow:
		return "USAF"
	if "army" in branchlow:
		return "USA"
	if "navy" in branchlow:
		return "USN"
	else:
		return ""

def parse_name(name):
	name = name.replace("Air Force Base", "AFB")
	name = name.replace("Joint Base", "JB")
	return name

def generate_varname(name):
	name = name.lower()
	bad_chars = [".", "-", "–"]
	for char in bad_chars:
		name = name.replace(char, "")
	name = name.replace(" ", "_")
	return name

def format_date(date):
	return date.strftime("%b %Y")
