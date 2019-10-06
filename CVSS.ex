defmodule CVSS do
	require Regex

	@moduledoc """
	//////////////////////////////////////////////////////////////////////////////
	// CVSS CALCULATOR
	//   by Gerardo García Peña
	//////////////////////////////////////////////////////////////////////////////
	"""

	defstruct [
		:CVSS,
		:AV,	:"AV/v",
		:AC,	:"AC/v",
		:PR,	:"PR/v",
		:UI,	:"UI/v",
		:S,	:"S/v",
		:C,	:"C/v",
		:I,	:"I/v",
		:A,	:"A/v",
		:E,	:"E/v",
		:RL,	:"RL/v",
		:RC,	:"RC/v",
		:CR,	:"CR/v",
		:IR,	:"IR/v",
		:AR,	:"AR/v",
		:MAV,	:"MAV/v",
		:MAC,	:"MAC/v",
		:MPR,	:"MPR/v",
		:MUI,	:"MUI/v",
		:MS,	:"MS/v",
		:MC,	:"MC/v",
		:MI,	:"MI/v",
		:MA,	:"MA/v",
		:Au,	:"Au/v",
		:CDP,	:"CDP/v",
		:TD,	:"TD/v",
		:"BaseScore/v",
		:"ImpactSubScore/v",
		:"TemporalScore/v",
		:"ExploitabilitySubScore/v",
		:"ModifiedImpactSubScore/v",
		:"ModifiedExploitabilitySubScore/v",
		:"EnvScore/v",
		:"OverallScore/v"
	]

	@cvss_consts %{
		v3: %{
			AV: %{
				r: ~r/^attack *vector$/i,
				v: %{ N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
				c: [
					[ ~r/^ n $/ix, ~r/^ network  $/ix ],
					[ ~r/^ a $/ix, ~r/^ adjacent $/ix ],
					[ ~r/^ l $/ix, ~r/^ local    $/ix ],
					[ ~r/^ p $/ix, ~r/^ physical $/ix ]
				]
			},
			AC: %{
				r: ~r/^attack *complexity$/i,
				v: %{ L: 0.77, H: 0.44 },
				c: [
					[ ~r/^ l $/ix, ~r/^ low  $/ix ],
					[ ~r/^ h $/ix, ~r/^ high $/ix ]
				]
			},
			PR: %{
				r: ~r/^privileges *required$/i,
				v: %{
					C: %{ N: 0.85, L: 0.68, H: 0.50 }, # scope changed
					U: %{ N: 0.85, L: 0.62, H: 0.27 }  # scope unchanged
				},
				c: [
					[ ~r/^ n $/ix, ~r/^ none $/ix ],
					[ ~r/^ l $/ix, ~r/^ low  $/ix ],
					[ ~r/^ h $/ix, ~r/^ high $/ix ]
				]
			},
			UI: %{
				r: ~r/^user *interaction$/i,
				v: %{ N: 0.85,   R: 0.62       },
				c: [
					[ ~r/^ n $/ix, ~r/^ none     $/ix ],
					[ ~r/^ r $/ix, ~r/^ required $/ix ]
				]
			},
			S: %{
				r: ~r/^scope$/i,
				v: %{ U: 0.00, C: 0.00 },
				c: [
					[ ~r/^ u $/ix, ~r/^ unchanged $/ix ],
					[ ~r/^ c $/ix, ~r/^ changed   $/ix ],
				]
			},
			CIA: %{
				r: ~r/^(confidentiality|integrity|availability) *impact$/i,
				v: %{ H: 0.56, L: 0.22, N: 0.00 },
				c: [
					[ ~r/^ h $/ix, ~r/^ high $/ix ],
					[ ~r/^ l $/ix, ~r/^ low  $/ix ],
					[ ~r/^ n $/ix, ~r/^ none $/ix ]
				]
			},
			C: "alias(CIA)",
			I: "alias(CIA)",
			A: "alias(CIA)",
			E: %{
				r: ~r/^exploit *(code *)?maturity$/i,
				v: %{ U: 0.91, P: 0.94, F: 0.97, H: 1.00 },
				c: [
					[ ~r/^ u $/ix, ~r/^ unproven               $/ix ],
					[ ~r/^ p $/ix, ~r/^ (poc|proof-of-concept) $/ix ],
					[ ~r/^ f $/ix, ~r/^ functional             $/ix ],
					[ ~r/^ h $/ix, ~r/^ high                   $/ix ]
				]
			},
			RL: %{
				r: ~r/^remediation *level$/i,
				v: %{ U: 1.00, W: 0.97, T: 0.96, O: 0.95 },
				c: [
					[ ~r/^ u $/ix, ~r/^ (unavailable          |hard     ) $/ix ],
					[ ~r/^ w $/ix, ~r/^ (workaround           |difficult) $/ix ],
					[ ~r/^ t $/ix, ~r/^ (temporary (\s+ fix)? |normal   ) $/ix ],
					[ ~r/^ o $/ix, ~r/^ (official  (\s+ fix)? |easy     ) $/ix ]
				]
			},
			RC: %{
				r: ~r/^report *confidence$/i,
				v: %{ C: 1.00, R: 0.96, U: 0.92 },
				c: [
					[ ~r/^ c $/ix, ~r/^ confirmed  $/ix ],
					[ ~r/^ r $/ix, ~r/^ reasonable $/ix ],
					[ ~r/^ u $/ix, ~r/^ unknown    $/ix ]
				]
			},
			SR: %{
				r: ~r/^(confidentiality|integrity|availability) *required$/i,
				v: %{ H: 1.50, M: 1.00, L: 0.50 },
				c: [
					[ ~r/^ h $/ix, ~r/^ high   $/ix ],
					[ ~r/^ m $/ix, ~r/^ medium $/ix ],
					[ ~r/^ l $/ix, ~r/^ low    $/ix ]
				]
			},
			CR: "alias(SR)",
			IR: "alias(SR)",
			AR: "alias(SR)",
			MAV: %{
				r: ~r/^mod(ified|\.)? *attack *vector$/i,
				v: %{ N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
				c: [
					[ ~r/^ n $/ix, ~r/^ network  $/ix ],
					[ ~r/^ a $/ix, ~r/^ adjacent $/ix ],
					[ ~r/^ l $/ix, ~r/^ local    $/ix ],
					[ ~r/^ p $/ix, ~r/^ physical $/ix ]
				]
			},
			MAC: %{
				r: ~r/^mod(ified|\.)? *attack *complexity$/i,
				v: %{ L: 0.77, H: 0.44 },
				c: [
					[ ~r/^ l $/ix, ~r/^ low  $/ix ],
					[ ~r/^ h $/ix, ~r/^ high $/ix ]
				]
			},
			MPR: %{
				r: ~r/^mod(ified|\.)? *privileges *required$/i,
				v: %{
					C: %{ N: 0.85, L: 0.68, H: 0.50 }, # scope changed
					U: %{ N: 0.85, L: 0.62, H: 0.27 }  # scope unchanged
				},
				c: [
					[ ~r/^ n $/ix, ~r/^ none $/ix ],
					[ ~r/^ l $/ix, ~r/^ low  $/ix ],
					[ ~r/^ h $/ix, ~r/^ high $/ix ]
				]
			},
			MUI: %{
				r: ~r/^mod(ified|\.)? *user *interaction$/i,
				v: %{ N: 0.85, R: 0.62 },
				c: [
					[ ~r/^ n $/ix, ~r/^ none     $/ix ],
					[ ~r/^ r $/ix, ~r/^ required $/ix ]
				]
			},
			MS: %{
				r: ~r/^mod(ified|\.)? *scope$/i,
				v: %{ U: 0.00, C: 0.00 },
				c: [
					[ ~r/^ u $/ix, ~r/^ unchanged $/ix ],
					[ ~r/^ c $/ix, ~r/^ changed   $/ix ]
				]
			},
			MCIA: %{
				r: ~r/^mod(ified|\.)? *(confidentiality|integrity|availability) *impact$/i,
				v: %{ H: 0.56, L: 0.22, N: 0.00 },
				c: [
					[ ~r/^ h $/ix, ~r/^ high $/ix ],
					[ ~r/^ l $/ix, ~r/^ low  $/ix ],
					[ ~r/^ n $/ix, ~r/^ none $/ix ]
				]
			},
			MC: "alias(MCIA)",
			MI: "alias(MCIA)",
			MA: "alias(MCIA)",
		},
		v2: %{
			AV: %{
				r: ~r/^access *vector$/i,
				v: %{ L: 0.395, A: 0.646, N: 1.000 },
				c: [
					[ ~r/^ l $/ix, ~r/^ local                                         $/ix ],
					[ ~r/^ a $/ix, ~r/^ (local \s+ network | adjacent (\s+ network)?) $/ix ],
					[ ~r/^ n $/ix, ~r/^ network                                       $/ix ]
				]
			},
			AC: %{
				r: ~r/^access *complexity$/i,
				v: %{ L: 0.71, M: 0.61, H: 0.35 },
				c: [
					[ ~r/^ l $/ix, ~r/^ low    $/ix ],
					[ ~r/^ m $/ix, ~r/^ medium $/ix ],
					[ ~r/^ h $/ix, ~r/^ high   $/ix ]
				]
			},
			Au: %{
				r: ~r/^authentication$/i,
				v: %{ M: 0.450, S: 0.560, N: 0.704 },
				c: [
					[ ~r/^ m $/ix, ~r/^ multiple $/ix ],
					[ ~r/^ s $/ix, ~r/^ single   $/ix ],
					[ ~r/^ n $/ix, ~r/^ none     $/ix ]
				]
			},
			CIA: %{
				r: ~r/^(confidentiality|integrity|availability) *impact$/i,
				v: %{ N: 0.000, P: 0.275, C: 0.660 },
				c: [
					[ ~r/^ n $/ix, ~r/^ none            $/ix ],
					[ ~r/^ p $/ix, ~r/^ partial         $/ix ],
					[ ~r/^ c $/ix, ~r/^ (complete|full) $/ix ]
				]
			},
			C: "alias(CIA)",
			I: "alias(CIA)",
			A: "alias(CIA)",
			E: %{
				r: ~r/^exploitability$/i,
				v: %{ U: 0.85, P: 0.90, POC: 0.90, F: 0.95, H: 1.00 },
				c: [
					[ ~r/^ u      $/ix, ~r/^ unproven               $/ix ],
					[ ~r/^ p(oc)? $/ix, ~r/^ (poc|proof-of-concept) $/ix ],
					[ ~r/^ f      $/ix, ~r/^ functional             $/ix ],
					[ ~r/^ h      $/ix, ~r/^ high                   $/ix ]
				]
			},
			RL: %{
				r: ~r/^remediation *level$/i,
				v: %{ U: 1.00, W: 0.95, T: 0.90, TF: 0.90, O: 0.87, OF: 0.87 },
				c: [
					[ ~r/^ u   $/ix, ~r/^ (unavailable       |hard)      $/ix ],
					[ ~r/^ w   $/ix, ~r/^ (workaround        |difficult) $/ix ],
					[ ~r/^ tf? $/ix, ~r/^ (temporary \s+ fix |normal)    $/ix ],
					[ ~r/^ of? $/ix, ~r/^ (official \s+ fix  |easy)      $/ix ]
				]
			},
			RC: %{
				r: ~r/^report *confidence$/i,
				v: %{ UC: 0.90, UR: 0.95, C: 1.00 },
				c: [
					[ ~r/^ uc $/ix, ~r/^ unconfirmed    $/ix ],
					[ ~r/^ ur $/ix, ~r/^ uncorroborated $/ix ],
					[ ~r/^ c  $/ix, ~r/^ confirmed      $/ix ]
				]
			},
			CIAR: %{
				r: ~r/^(confidentiality|integrity|availability) *requirement$/i,
				v: %{ L: 0.50,  M: 1.00, H: 1.51 },
				c: [
					[ ~r/^ l $/ix, ~r/^ low    $/ix ],
					[ ~r/^ m $/ix, ~r/^ medium $/ix ],
					[ ~r/^ h $/ix, ~r/^ high   $/ix ]
				]
			},
			CR: "alias(CIAR)",
			IR: "alias(CIAR)",
			AR: "alias(CIAR)",
			CDP: %{
				r: ~r/^collateral *damage *potential$/i,
				v: %{ N: 0.0, L: 0.1, LM: 0.3, MH: 0.4, H: 0.5 },
				c: [
					[ ~r/^ n  $/ix, ~r/^ none        $/ix ],
					[ ~r/^ l  $/ix, ~r/^ low         $/ix ],
					[ ~r/^ lm $/ix, ~r/^ low-medium  $/ix ],
					[ ~r/^ mh $/ix, ~r/^ medium-high $/ix ],
					[ ~r/^ h  $/ix, ~r/^ high        $/ix ]
				]
			},
			TD: %{
				r: ~r/^target *distribution$/i,
				v: %{ N: 0.00, L: 0.25, M: 0.75, H: 1.00 },
				c: [
					[ ~r/^ n $/ix, ~r/^ none   $/ix ],
					[ ~r/^ l $/ix, ~r/^ low    $/ix ],
					[ ~r/^ m $/ix, ~r/^ medium $/ix ],
					[ ~r/^ h $/ix, ~r/^ high   $/ix ]
				]
			}
		}
	}

	@doc """
	Private function for retrieving constants from the CVSS_constants mega
	dictionary

		@param {atom|str|list(atom|str)} path
					Path
		@param {root} root	Root hash (CVSS.constants)
		@return sub dictionary or constant
	"""
	def cvss_get_constant(str),                        do: cvss_get_constant(str, @cvss_consts)
	def cvss_get_constant(str, h) when is_binary(str), do: CVSS.cvss_get_constant([str], h)
	def cvss_get_constant([head | tail], h) when is_binary(head) do
		CVSS.cvss_get_constant(
			Enum.map(
				String.split(head, "."), &(String.to_existing_atom(&1))) ++ tail,
				h)
	end
	def cvss_get_constant([head | tail], h) when is_atom(head) and is_map(h) do
		if not Map.has_key?(h, head), do: raise "Entry '#{head}' not found in constants"
		CVSS.cvss_get_constant(tail, h[head])
	end
	def cvss_get_constant([head | tail], h) when is_atom(head) and is_binary(h) do
		alias = Regex.named_captures(~r/^alias \( (?<alias> [^\)]+ ) \)$/x, "h")[:alias]
		if nil == alias, do: raise "Cannot follow value '#{head}'"
		CVSS.cvss_get_constant(tail, alias)
	end
	def cvss_get_constant([], h), do: h

	# Private function that implements the CVSS round function (ceiling
	# round)
	# 
	# 	@param {Number} x	float value.
	# 	@return {Number} value round to the nearest upper integer.
	defp cvss_v3_round_up(nil), do: nil
	defp cvss_v3_round_up(x), do: Float.ceil(x, 1)
	defp cvss_v2_round_up(nil), do: nil
	defp cvss_v2_round_up(x), do: Float.round(x, 1)

	@doc """
	This private function returns the appropiate short "Not defined"
	string for the CVSS version passed as argument.

		@param {String} cvss_version
					The CVSS version
		@return {String} Not defiend string
	"""
	def cvss_not_defined_string(cvss) when is_map(cvss), do: cvss_not_defined_string(Map.fetch!(cvss, :CVSS))
	def cvss_not_defined_string("2.0"), do: :ND
	def cvss_not_defined_string(_), do: :X

	def cvss_get_version_vector(cvss) do
		Map.fetch!(cvss, :CVSS)
	end

	@doc """
	This private function gets the vector value of a CVSS object.

		@param {CVSS} cvss	CVSS object
		@param {str/atom} vector
					Vector
		@return {nil/String} vector value
	"""
	def cvss_get_vector(cvss, vector) when is_atom(vector) do
		if (Map.has_key?(cvss, vector)
			and Map.fetch!(cvss, vector) != ""
			and Map.fetch!(cvss, vector) != cvss_not_defined_string(cvss)) do
				Map.fetch!(cvss, vector)
		else
			nil
		end
	end
	def cvss_get_vector(cvss, vector) when is_binary(vector) do
		cvss_get_vector(cvss, String.to_existing_atom(vector))
	end
	def cvss_get_vector_value(cvss, vector) do
		cvss_get_vector(cvss, "#{vector}/v")
	end

	@doc """
	This private function tells if the vector is set (even if undefined)

		@param {CVSS} cvss	CVSS object
		@param {str/atom} vector
					Vector
		@return {nil/String} vector status
	"""
	def cvss_is_vector_set(cvss, vector) when is_atom(vector) do
		(Map.fetch!(cvss, vector) != nil and Map.fetch!(cvss, vector) != "")
	end
	def cvss_is_vector_set(cvss, vector) when is_binary(vector) do
		cvss_is_vector_set(cvss, String.to_existing_atom(vector))
	end

	@doc """
	This private function sets the vector value of a CVSS object.

		@param {CVSS} cvss	CVSS object
		@param {str/atom} vector
					Vector
		@param {value} value    Value
		@return {CVSS} CVSS object
	"""
	def cvss_set_vector(cvss, vector, value) when is_atom(vector) do
		if (value != nil
			and value != ""
			and value != cvss_not_defined_string(cvss)) do
			Map.put(cvss, vector, value)
		else
			Map.delete(cvss, vector)
		end
	end
	def cvss_set_vector(cvss, vector, value) when is_binary(vector) do
		cvss_set_vector(cvss, String.to_existing_atom(vector), value)
	end
	def cvss_set_vector_value(cvss, vector, value) do
		cvss_set_vector(cvss, "#{vector}/v", value)
	end

	# This private function checks if vector value is not defined.
	# 
	# 	@param {CVSS} cvss	A CVSS object
	# 	@param {String/atom} vector
	# 				The vector
	# 	@return {Boolean} True if defined, false elsewhere
	defp cvss_is_vector_defined(cvss, vector) when not is_list(vector) do
		cvss_get_vector(cvss, vector) != nil
	end
	defp cvss_is_vector_defined(_, []), do: true
	defp cvss_is_vector_defined(cvss, [head | tail]) do
		cvss_is_vector_defined(cvss, head) and cvss_is_vector_defined(cvss, tail)
	end

	defp cvss_is_vector_defined_or(cvss, vector) when not is_list(vector) do
		cvss_get_vector(cvss, vector) != nil
	end
	defp cvss_is_vector_defined_or(_, []), do: false
	defp cvss_is_vector_defined_or(cvss, [head | tail]) do
		cvss_is_vector_defined_or(cvss, head) or cvss_is_vector_defined_or(cvss, tail)
	end

	# Private function that gets the CVSS stringification of a CVSS object.
	# 
	# 	@param  {CVSS} cvss	The CVSS object.
	# 	@return {String} The CVSS string representation of the CVSS
	# 			object.
	defp cvss_get_string_fields("2.0"), do: [ :AV, :AC, :Au, :C, :I, :A, :E, :RL, :RC, :CDP, :TD, :CR, :IR, :AR ]
	defp cvss_get_string_fields("3.0"), do: [ :CVSS, :AV, :AC, :PR, :UI, :S, :C, :I, :A, :E, :RL, :RC, :CR, :IR, :AR, :MAV, :MAC, :MPR, :MUI, :MS, :MC, :MI, :MA ]
	defp cvss_get_string_fields("3.1"), do: cvss_get_string_fields("3.0")
	def cvss_get_string(cvss) do
		cvss_get_string_fields(cvss_get_version_vector(cvss))
		|> Enum.filter(fn e -> cvss_is_vector_set(cvss, e) end)
		|> Enum.map(fn e -> "#{e}:#{cvss_get_vector(cvss, e) || cvss_not_defined_string(cvss)}" end)
		|> Enum.join("/")
	end

	@doc """
	Private function for calculing the score of some vectors using the
	description found in the provided dictionaries and values
	
		@param {CVSS} cvss     the CVSS object being calculated
		@param {String} v        the CVSS vector being calculated
		@param {Map} values   vector's valid values
		@param {String} defvalue   default value
	"""
	def cvss_vector_calc_score(cvss, vector, values, defvalue) do
		value = if cvss_is_vector_defined(cvss, vector),
			do: cvss_get_vector(cvss, vector),
			else: defvalue
		if not Map.has_key?(values, value) do
			raise "Invalid value '#{value}' in vector '#{vector}'"
		end
		cvss_set_vector_value(cvss, vector, values[value])
	end
	def cvss_vector_calc_score(cvss, vector, values) do
		cvss_vector_calc_score(cvss, vector, values, nil)
	end

	#  Private function that performs the CVSSv3 calculations on input object.
	# 
	# 	@param {CVSS} cvss  A CVSS object
	# 	@return {CVSS} A CVSS object
	defp cvss_v3_calculate(cvss, subversion) do
		# Calculate CVSS vector scores
		cvss = cvss_set_vector_value(cvss, :S, cvss_get_vector(cvss, :S))
		cvss = cvss_set_vector_value(
				cvss, :MS,
				cvss_get_vector(
					cvss,
					(if cvss_is_vector_defined(cvss, :MS),
						do: :MS,
						else: "S/v")))
		#[ "S", "MS" ].forEach(
		#function(v) {
		#if(cvss[v + "/v"] != "U" && cvss[v + "/v"] != "C")
		#__CVSS_raise_error(cvss, "__CVSSv3_calculate", Utilities.formatString("Invalid value '%s' in vector '%s'", cvss[v + "/v"], v));
		#});
		cvss = cvss_vector_calc_score(cvss, :AV,  cvss_get_constant(["v3.AV.v"]))
		cvss = cvss_vector_calc_score(cvss, :AC,  cvss_get_constant(["v3.AC.v"]))
		cvss = cvss_vector_calc_score(cvss, :PR,  cvss_get_constant(["v3.PR.v", cvss_get_vector_value(cvss, :S)]))
		cvss = cvss_vector_calc_score(cvss, :UI,  cvss_get_constant(["v3.UI.v"]))
		cvss = cvss_vector_calc_score(cvss, :MAV, cvss_get_constant(["v3.AV.v"]),                                   cvss_get_vector(cvss, :AV))
		cvss = cvss_vector_calc_score(cvss, :MAC, cvss_get_constant(["v3.AC.v"]),                                   cvss_get_vector(cvss, :AC))
		cvss = cvss_vector_calc_score(cvss, :MPR, cvss_get_constant(["v3.PR.v", cvss_get_vector_value(cvss, :MS)]), cvss_get_vector(cvss, :PR))
		cvss = cvss_vector_calc_score(cvss, :MUI, cvss_get_constant(["v3.UI.v"]),                                   cvss_get_vector(cvss, :UI))
		cvss = cvss_vector_calc_score(cvss, :E,   cvss_get_constant(["v3.E.v"]),                                    :H)
		cvss = cvss_vector_calc_score(cvss, :RL,  cvss_get_constant(["v3.RL.v"]),                                   :U)
		cvss = cvss_vector_calc_score(cvss, :RC,  cvss_get_constant(["v3.RC.v"]),                                   :C)
		cvss = Enum.reduce(
			[ :C, :I, :A ],
			cvss,
			fn v, cvss ->
				cvss = cvss_vector_calc_score(cvss, v,       cvss_get_constant("v3.CIA.v"))
				cvss = cvss_vector_calc_score(cvss, "M#{v}", cvss_get_constant("v3.CIA.v"), cvss_get_vector(cvss, v))
				cvss = cvss_vector_calc_score(cvss, "#{v}R", cvss_get_constant("v3.SR.v"),  :M)
				cvss
			end)

		# CALCULATE THE CVSS BASE SCORE
		impactSubScoreMultiplier = (
			1.0 - ((1.0 - cvss_get_vector_value(cvss, :C))
			     * (1.0 - cvss_get_vector_value(cvss, :I))
			     * (1.0 - cvss_get_vector_value(cvss, :A))))
		impactSubScore = 
			if cvss_get_vector_value(cvss, :S) == :U,
				do:   6.42 * impactSubScoreMultiplier,
				else: 7.52 * (impactSubScoreMultiplier - 0.029) - 3.25 * :math.pow(impactSubScoreMultiplier - 0.02, 15)
		exploitabilitySubScore = (
			8.22
			* cvss_get_vector_value(cvss, :AV)
			* cvss_get_vector_value(cvss, :AC)
			* cvss_get_vector_value(cvss, :PR)
			* cvss_get_vector_value(cvss, :UI))
		baseScore = cvss_v3_round_up(
				if impactSubScore <= 0 do
					0.0
				else
					min(
						10.0,
						(if cvss_get_vector_value(cvss, :S) == :U, do: 1.0, else: 1.08)
							* (exploitabilitySubScore + impactSubScore)
					)
				end)

		# CALCULATE THE CVSS TEMPORAL SCORE
		temporalScore = 
			if cvss_is_vector_defined_or(cvss, [:E, :RL, :RC]) do
				cvss_v3_round_up(
					baseScore
				      * cvss_get_vector_value(cvss, :E)
				      * cvss_get_vector_value(cvss, :RL)
				      * cvss_get_vector_value(cvss, :RC))
			else
				nil
			end

		# CALCULATE THE CVSS ENVIRONMENTAL SCORE
		modifiedImpactSubScoreMultiplier =
			min(
				1 - ((1 - cvss_get_vector_value(cvss, :MC) * cvss_get_vector_value(cvss, :CR))
				   * (1 - cvss_get_vector_value(cvss, :MI) * cvss_get_vector_value(cvss, :IR))
				   * (1 - cvss_get_vector_value(cvss, :MA) * cvss_get_vector_value(cvss, :AR))),
				0.915)

		modifiedImpactSubScore =
			(if cvss_get_vector_value(cvss, :MS) == :U,
				do:   (6.42 * modifiedImpactSubScoreMultiplier),
				else: (7.52 * (modifiedImpactSubScoreMultiplier - 0.029) - 3.25 * :math.pow(
						(if subversion == 0, do: 1.00, else: 0.9731) * modifiedImpactSubScoreMultiplier - 0.02,
						(if subversion == 0, do: 15,    else: 13))))

		modifiedExploitabilitySubScore =
			if cvss_is_vector_defined_or(cvss, [:MAV, :MAC, :MPR, :MUI])
				do
					8.22 * cvss_get_vector_value(cvss, :MAV)
					     * cvss_get_vector_value(cvss, :MAC)
					     * cvss_get_vector_value(cvss, :MPR)
					     * cvss_get_vector_value(cvss, :MUI)
				else
					nil
				end

		envScore =
			if (cvss_is_vector_defined_or(cvss, [:MS, :E, :RL, :RC])
				and modifiedImpactSubScore != nil
				and modifiedExploitabilitySubScore != nil)
			do
				cvss_v3_round_up(
					(if modifiedImpactSubScore <= 0,
						do:   0,
						else: min(
							(if cvss_get_vector_value(cvss, :MS) == :U, do: 1.0, else: 1.08)
								* (modifiedImpactSubScore + modifiedExploitabilitySubScore),
							10))
					* cvss_get_vector_value(cvss, :E)
					* cvss_get_vector_value(cvss, :RL)
					* cvss_get_vector_value(cvss, :RC))
			else
				nil
			end

		# fix scores
		impactSubScore         = cvss_v3_round_up(impactSubScore)
		exploitabilitySubScore = cvss_v3_round_up(exploitabilitySubScore)
		modifiedImpactSubScore = cvss_v3_round_up(modifiedImpactSubScore)

		# Set scores
		cvss
		|> cvss_set_vector_value(:BaseScore, baseScore)
		|> cvss_set_vector_value(:ImpactSubScore, impactSubScore)
		|> cvss_set_vector_value(:ExploitabilitySubScore, exploitabilitySubScore)
		|> cvss_set_vector_value(:TemporalScore, temporalScore)
		|> cvss_set_vector_value(:EnvScore, envScore)
		|> cvss_set_vector_value(:ModifiedImpactSubScore, modifiedImpactSubScore)
		|> cvss_set_vector_value(:ModifiedExploitabilitySubScore, modifiedExploitabilitySubScore)
		|> cvss_set_vector_value(:OverallScore, envScore || temporalScore || baseScore)
	end

	# Private function that performs the CVSSv2 calculations on input object.
	# 
	#  @param {Object} cvss  A CVSSv2 object
	# 
	defp cvss_v2_calculate(cvss) do
		# Calculate CVSS vector scores
		cvss = cvss
			|> cvss_vector_calc_score(:AV,   cvss_get_constant("v2.AV.v"),  :N)
			|> cvss_vector_calc_score(:AC,   cvss_get_constant("v2.AC.v"),  :L)
			|> cvss_vector_calc_score(:Au,   cvss_get_constant("v2.Au.v"),  :N)
			|> cvss_vector_calc_score(:E,    cvss_get_constant("v2.E.v"),   :H)
			|> cvss_vector_calc_score(:RL,   cvss_get_constant("v2.RL.v"),  :U)
			|> cvss_vector_calc_score(:RC,   cvss_get_constant("v2.RC.v"),  :C)
			|> cvss_vector_calc_score(:CDP,  cvss_get_constant("v2.CDP.v"), :N)
			|> cvss_vector_calc_score(:TD,   cvss_get_constant("v2.TD.v"),  :H)
		cvss = Enum.reduce(
			[ :C, :I, :A ],
			cvss,
			fn v, cvss ->
				cvss
				|> cvss_vector_calc_score(v,       cvss_get_constant("v2.CIA.v"))
				|> cvss_vector_calc_score("#{v}R", cvss_get_constant("v2.CIAR.v"), :M)
			end)

		# CALCULATE THE CVSS BASE SCORE
		impactSubScore =
			(10.41
			* (1 - ((1 - cvss_get_vector_value(cvss, :C))
			      * (1 - cvss_get_vector_value(cvss, :I))
			      * (1 - cvss_get_vector_value(cvss, :A)))))
		exploitabilitySubScore = (
				20.00
				* cvss_get_vector_value(cvss, :AC)
				* cvss_get_vector_value(cvss, :Au)
				* cvss_get_vector_value(cvss, :AV))
		fImpact = if impactSubScore <= 0, do: 0.000, else: 1.176
		baseScore = cvss_v2_round_up(((0.6 * impactSubScore) + (0.4 * exploitabilitySubScore) - 1.5) * fImpact)

		# CALCULATE THE CVSS TEMPORAL SCORE
		temporalScore =
			if cvss_is_vector_defined_or(cvss, [:E, :RL, :RC]) do
				cvss_v2_round_up(
					baseScore
					* cvss_get_vector_value(cvss, :E)
					* cvss_get_vector_value(cvss, :RL)
					* cvss_get_vector_value(cvss, :RC))
			else
				nil
			end

		# CALCULATE THE CVSS ENVIRONMENTAL SCORE
		adjustedImpact =
			if cvss_is_vector_defined_or(cvss, [:CR, :IR, :AR]) do
				min(
					10.00,
					10.41
					* (1 - ((1 - cvss_get_vector_value(cvss, :C) * cvss_get_vector_value(cvss, :CR))
					      * (1 - cvss_get_vector_value(cvss, :I) * cvss_get_vector_value(cvss, :IR))
					      * (1 - cvss_get_vector_value(cvss, :A) * cvss_get_vector_value(cvss, :AR)))))
			else
				nil
			end
		adjustedTemporal =
			if (cvss_is_vector_defined_or(cvss, [:E, :RL, :RC]) and adjustedImpact != nil) do
				((((0.6 * adjustedImpact) + (0.4 * exploitabilitySubScore) - 1.5) * fImpact)
				* cvss_get_vector_value(cvss, :E)
				* cvss_get_vector_value(cvss, :RL)
				* cvss_get_vector_value(cvss, :RC))
			else
				nil
			end
		envScore =
			if (cvss_is_vector_defined_or(cvss, [:CDP, :TD]) and adjustedTemporal != nil) do
				cvss_v2_round_up(
					(adjustedTemporal + (10 - adjustedTemporal) * cvss_get_vector_value(cvss, :CDP))
					* cvss_get_vector_value(cvss, :TD))
			else
				nil
			end

		# fix scores
		impactSubScore         = cvss_v2_round_up(impactSubScore)
		exploitabilitySubScore = cvss_v2_round_up(exploitabilitySubScore)

		# CALCULATE OVERALL SCORE
		cvss
		|> cvss_set_vector_value(:BaseScore,              baseScore)
		|> cvss_set_vector_value(:ImpactSubScore,         impactSubScore)
		|> cvss_set_vector_value(:ExploitabilitySubScore, exploitabilitySubScore)
		|> cvss_set_vector_value(:TemporalScore,          temporalScore)
		|> cvss_set_vector_value(:EnvScore,               envScore)
		|> cvss_set_vector_value(:OverallScore,           envScore || temporalScore || baseScore)
	end

	@doc """
	Private function that performs the CVSS calculations on the input object.
	
		@param {Object} cvss  A CVSS object
	"""
	def cvss_calculate(cvss) do
		# detect version
		cvss = if (not Map.has_key?(cvss, :CVSS)
				or cvss_get_version_vector(cvss) == nil
				or cvss_get_version_vector(cvss) == ""),
			do: Map.put(cvss, :CVSS,
				(if Map.has_key?(cvss, :S) or Map.has_key?(cvss, :PR) or Map.has_key?(cvss, :UI),
					do: "2.0",
					else: "3.1")),
			else: cvss

		# SPECIFIC PARSING AND CALCULATIONS FOR EACH VERSION
		cvss = case cvss_get_version_vector(cvss) do
			  "2.0" -> cvss_v2_calculate(cvss)
			  "3.0" -> cvss_v3_calculate(cvss, 0)
			  "3.1" -> cvss_v3_calculate(cvss, 1)
			  _ ->
				raise "Unknown CVSS version '#{cvss_get_version_vector(cvss)}'"
		end
	  
		# CALCULATE REMEDIATION SCORE LEVEL
		if cvss_is_vector_defined(cvss, :RL),
			do: cvss_set_vector_value(cvss, :RL,
				case cvss_get_vector(cvss, :RL) do
					"U" -> 1.00
					"W" -> 3.00
					"T" -> 4.00
					"O" -> 5.00
					_ -> 5.00
				end),
			else: cvss
	end
	
	@doc """
	Private function that parses a CVSS string, calculates it and returns a
	CVSS object reference.

	  @param {String} cvss_string  A CVSS string.
	  @return {Object} A CVSS object.
	"""
	def cvss_parse_string(cvss_string) do
		# split in parts and hashify and calculate
		struct(CVSS,
			String.upcase(cvss_string)
			|> String.split("/")
			|> Enum.map(&String.split(&1, ":"))
			|> Enum.map(fn [x, y] ->
				[
					String.to_existing_atom(if x == "AU", do: "Au", else: x),
					(if x != "CVSS", do: String.to_existing_atom(y), else: y)
				] end)
			|> Map.new(&List.to_tuple/1))
		|> cvss_calculate
	end
end

defmodule Test do
	def i(t) do
		IO.puts(
			IO.ANSI.reset()
			<> "["
			<> IO.ANSI.light_black()
			<> "--"
			<> IO.ANSI.reset()
			<> "] #{t}")
	end

	def i(t, x) do
		IO.puts(
			IO.ANSI.reset()
			<> "["
			<> IO.ANSI.light_black()
			<> "--"
			<> IO.ANSI.reset()
			<> "] #{t}: "
			<> inspect(x, [pretty: true, syntax_colors: [number: :yellow, atom: :cyan, string: :green, boolean: :magenta, nil: :magenta]]))
	end

	def i(t, x, expected, strict) do
		IO.puts(
			IO.ANSI.reset()
			<> "["
			<> (if x == expected,
				do: IO.ANSI.green() <> "OK",
				else:
					(if strict,
						do: IO.ANSI.red() <> "KO",
						else: IO.ANSI.yellow() <> "!!"))
			<> IO.ANSI.reset()
			<> "] #{t}: "
			<> inspect(x, [pretty: true, syntax_colors: [number: :yellow, atom: :cyan, string: :green, boolean: :magenta, nil: :magenta]]))
		if strict and x != expected, do: raise "BAD! Expected '#{expected}'"
	end

	def i(t, x, expected) do
		i(t, x, expected, true)
	end
end

# TEST
Enum.each(
	[
		# CVSS string                                                                                                              Base  Impact  Expl.  Temp.  Env.  Mod.  Overall
		# ------------------------------------------------                                                                         ----- ------- ------ ------ ----- ----- -------
		[ "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",                                                                          7.5,    3.6,   3.9,    nil,  nil,  nil,     7.5 ],
		[ "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",                                                                          6.5,    3.6,   2.8,    nil,  nil,  nil,     6.5 ],
		[ "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",                                                                          4.2,    3.6,   0.5,    nil,  nil,  nil,     4.2 ],
		[ "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N",                                                                          4.9,    3.6,   1.2,    nil,  nil,  nil,     4.9 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L",                                                                          9.2,    6.0,   2.5,    nil,  nil,  nil,     9.2 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:U/RL:X/RC:X",                                                            9.2,    6.0,   2.5,    8.4,  nil,  nil,     8.4 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:F/RL:X/RC:X",                                                            9.2,    6.0,   2.5,    9.0,  nil,  nil,     9.0 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:F/RL:W/RC:X",                                                            9.2,    6.0,   2.5,    8.7,  nil,  nil,     8.7 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:F/RL:W/RC:R",                                                            9.2,    6.0,   2.5,    8.4,  nil,  nil,     8.4 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:F/RL:W/RC:R/CR:X/IR:X/AR:X/MAV:N/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X", 9.2,    6.0,   2.5,    8.4,  9.1,  6.0,     9.1 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:F/RL:W/RC:R/MAV:N/MI:X/MA:X",                                            9.2,    6.0,   2.5,    8.4,  9.1,  6.0,     9.1 ],
		[ "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:L/E:F/RL:W/RC:R/CR:L/IR:M/AR:H/MAV:N/MAC:L/MPR:L/MUI:R/MS:U/MC:X/MI:N/MA:X", 9.2,    6.0,   2.5,    8.4,  4.9,  3.3,     4.9 ],

		[ "AV:N/AC:L/Au:N/C:P/I:C/A:P",                                                                                            9.0,    8.5,  10.0,    nil,  nil,  nil,     9.0 ],
		[ "AV:N/AC:L/Au:N/C:C/I:N/A:P",                                                                                            8.5,    7.8,  10.0,    nil,  nil,  nil,     8.5 ],
		[ "AV:N/AC:L/Au:N/C:C/I:N/A:P/E:U/RL:ND/RC:ND",                                                                            8.5,    7.8,  10.0,    7.2,  nil,  nil,     7.2 ],
		[ "AV:N/AC:L/Au:N/C:C/I:N/A:P/E:POC/RL:TF/RC:ND",                                                                          8.5,    7.8,  10.0,    6.9,  nil,  nil,     6.9 ],
		[ "AV:N/AC:L/Au:N/C:C/I:N/A:P/E:POC/RL:TF/RC:ND/CDP:L/TD:ND/CR:ND/IR:ND/AR:ND",                                            8.5,    7.8,  10.0,    6.9,  7.2,  7.8,     7.2 ],
	],
	fn test ->
		test = Enum.zip(
			[
				:str,
				:BaseScore,
				:ImpactSubScore,
				:ExploitabilitySubScore,
				:TemporalScore,
				:EnvScore,
				:ModifiedImpactSubScore,
				:OverallScore
			], test)
			|> Enum.reduce(%{}, fn {k, v}, a -> Map.put(a, k, v) end)
		cvss = CVSS.cvss_parse_string(test[:str])
		Test.i("cvss string", CVSS.cvss_get_string(cvss), test[:str])
		Enum.each([
				BaseScore:              true,
				ImpactSubScore:         false,
				ExploitabilitySubScore: false,
				TemporalScore:          true,
				EnvScore:               true,
				ModifiedImpactSubScore: false,
				OverallScore:           true
			],
			fn { score, strict } ->
				Test.i(score, CVSS.cvss_get_vector_value(cvss, score), test[score], strict)
			end)
	end)
