
# This code is an implementation of a CTR-DRBG (Counter-mode Deterministic Random Bit Generator)

# It implements most of the NIST SP 800-90A CTR-DRBG algorithm.
# It supports AES-128, AES-192, and AES-256, and implements DRBG instantiation, generation, reseeding, and update logic.
# It doesnt contain prediction resistance or the derivation function (DF).
# The code also has tests for a set of official test vectors, including standard and reseed scenarios with/without additional input.


from Crypto.Cipher import AES

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def inc128(counter):
    value = int.from_bytes(counter, 'big')
    value = (value + 1) % (1 << 128)
    return value.to_bytes(16, 'big')

def block_encrypt(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)

def to_bytes(hexstr):
    return bytes.fromhex(hexstr) if hexstr else b""

def drbg_update(provided_data, Key, V, keylen, do_xor=True):
    temp = b''
    blocklen = 16  
    temp_v = V
    while len(temp) < keylen + blocklen:
        temp_v = inc128(temp_v)
        temp += block_encrypt(Key, temp_v)
    temp = temp[:keylen + blocklen]
    if do_xor and provided_data and len(provided_data) > 0:
        provided_data = provided_data.ljust(keylen + blocklen, b'\x00')
        temp = xor_bytes(temp, provided_data)
    Key_new = temp[:keylen]
    V_new = temp[keylen:]
    return Key_new, V_new

def drbg_generate(Key, V, requested_bytes, keylen, additional_input=None):
    if additional_input and len(additional_input) > 0:
        additional_input = additional_input.ljust(keylen + 16, b'\x00')
        Key, V = drbg_update(additional_input, Key, V, keylen, do_xor=True)
        additional_input_for_final = additional_input
    else:
        additional_input_for_final = b'\x00' * (keylen + 16)

    temp = b''
    temp_v = V
    while len(temp) < requested_bytes:
        temp_v = inc128(temp_v)
        temp += block_encrypt(Key, temp_v)
    returned_bits = temp[:requested_bytes]
    V = temp_v

    Key, V = drbg_update(additional_input_for_final, Key, V, keylen, do_xor=True)
    return returned_bits, Key, V

def drbg_reseed(entropy_input, additional_input, Key, V, keylen):
    seed_material = entropy_input
    
    if additional_input and len(additional_input) > 0:
        if len(additional_input) < len(entropy_input):
            additional_input = additional_input.ljust(len(entropy_input), b'\x00')
        elif len(additional_input) > len(entropy_input):
            additional_input = additional_input[:len(entropy_input)]
        
        seed_material = xor_bytes(entropy_input, additional_input)
    
    Key_new, V_new = drbg_update(seed_material, Key, V, keylen, do_xor=True)
    return Key_new, V_new

test_vectors = [
    {
        "name": "CTR-DRBG AES-128 with no additional input",
        "keylen": 16,
        "entropy": "ce50f33da5d4c1d3d4004eb35244b7f2cd7f2e5076fbf6780a7ff634b249a5fc",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "96b20ff35faaf1b2e27f53e4f6a3f2a8",
        "expected_instantiate_v":   "cef7f49e164d55eaf957348dc3fb5b84",
        "generates": [
            {
                "additional_input": "",
                "expected_key": "2e8bf07c5a29b97633576a7c4d5343dd",
                "expected_v":   "3f93dbc9dc724d654f5f2a45b818c7ec",
                "returned_bits": None,
            },
            {
                "additional_input": "",
                "expected_key": "a103e1669b0641cae87caab70a741bf1",
                "expected_v":   "fbe9d7c15217c737b408e31679170140",
                "returned_bits": "6545c0529d372443b392ceb3ae3a99a30f963eaf313280f1d1a1e87f9db373d361e75d18018266499cccd64d9bbb8de0185f213383080faddec46bae1f784e5a"
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-128 with additional input",
        "keylen": 16,
        "entropy": "6bd4f2ae649fc99350951ff0c5d460c1a9214154e7384975ee54b34b7cae0704",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "33360e609ee1f9f266ea02a76133259b",
        "expected_instantiate_v":   "aaa99b9a878eeae71d7c71f20d1cf97c",
        "generates": [
            {
                "additional_input": "ecd4893b979ac92db1894ae3724518a2f78cf2dbe2f6bbc6fda596df87c7a4ae",
                "expected_key": "582aee70e7d4963ae26734497deb071f",
                "expected_v":   "81fd97877c660aa88aad40fa47b353fa",
                "returned_bits": None,
            },
            {
                "additional_input": "b23e9188687c88768b26738862c4791fa52f92502e1f94bf66af017c4228a0dc",
                "expected_key": "950ce1768cc9be9c0d58128f5c272605",
                "expected_v":   "fbf2e76077d5cbf6f316cc71a88ccd6d",
                "returned_bits": "5b2bf7a5c60d8ab6591110cbd61cd387b02de19784f496d1a109123d8b3562a5de2dd6d5d1aef957a6c4f371cecd93c15799d82e34d6a0dba7e915a27d8e65f3"
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-192 with no additional input",
        "keylen": 24,
        "entropy": "f1ef7eb311c850e189be229df7e6d68f1795aa8e21d93504e75abe78f041395873540386812a9a2a",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "3cdccc39d6bba7aa29b0f36ee5b1f2ba8f728ef22629cb45",
        "expected_instantiate_v": "fb7cc03b74f1cf5859609060e31f744d",
        "generates": [
            {
                "additional_input": "",
                "expected_key": "6bc37530d95aa756ce246323f8405086852578cff8c0c838",
                "expected_v": "eeb89f00f173069578102c405301173b",
                "returned_bits": None,
            },
            {
                "additional_input": "",
                "expected_key": "5e5ccdb3f2a74ba428f08cd465942ecedcacec77e93b1412",
                "expected_v": "528af6f2d453242e5cc77e24098bd66f",
                "returned_bits": "6bb0aa5b4b97ee83765736ad0e9068dfef0ccfc93b71c1d3425302ef7ba4635ffc09981d262177e208a7ec90a557b6d76112d56c40893892c3034835036d7a69",
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-192 with additional input",
        "keylen": 24,
        "entropy": "b895b891f039052821fbb4a889fced861b96c37e36a5f4f7aa208a2bf33a896fe7e29f3f6cf0041f",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "75a60a1b374af26381f5655b9babc9b38371e70231550ab6",
        "expected_instantiate_v": "b606f468778a7f6fcdd60cd90ec5ea78",
        "generates": [
            {
                "additional_input": "8711df3931a9035905ebdf510b3ea3f344923b2f20a561709c0def03b9570be267e9765719a25d8a",
                "expected_key": "8e7474c3cf68b27b2eabbeb913d74c02ac552d5e2d2dc980",
                "expected_v": "51124a2a7d78f44c8e964c8dabe81f63",
                "returned_bits": None,
            },
            {
                "additional_input": "03908b9fd56bad5a1645b688a4f9c2342bc0f81fed6f7449af14e92960d60127dda4e27487e77491",
                "expected_key": "67821a5f86c2e435eacfc582b6c1e881ab39c2c5a1b67d6a",
                "expected_v": "dddffec7dc810f11f44bdcff50f120db",
                "returned_bits": "1385397b1a245bd06bbb4bcf651a52b2d30867d3e2f98e9c7a9ee959d2e1bbd63a10054fc081cd22a7f3b65ed2f0b3a3deb389d2f336e50b359a6c3e83667fb1",
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-256 with no additional input",
        "keylen": 32,
        "entropy": "df5d73faa468649edda33b5cca79b0b05600419ccb7a879ddfec9db32ee494e5531b51de16a30f769262474c73bec010",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "8c52f901632d522774c08fad0eb2c33b98a701a1861aecf3d8a25860941709fd",
        "expected_instantiate_v": "217b52142105250243c0b2c206b8f59e",
        "generates": [
            {
                "additional_input": "",
                "expected_key": "72f4af5c93258eb3eeec8c0cacea6c1d1978a4fad44312725f1ac43b167f2d52",
                "expected_v": "e86f6d07dfb551cebad80e6bf6830ac4",
                "returned_bits": None,
            },
            {
                "additional_input": "",
                "expected_key": "1a1c6e5f1cccc6974436e5fd3f015bc8e9dc0f90053b73e3c19d4dfd66d1b85a",
                "expected_v": "53c78ac61a0bac9d7d2e92b1e73e3392",
                "returned_bits": "d1c07cd95af8a7f11012c84ce48bb8cb87189e99d40fccb1771c619bdf82ab2280b1dc2f2581f39164f7ac0c510494b3a43c41b7db17514c87b107ae793e01c5",
            }
        ]
    },

    {
        "name": "CTR-DRBG AES-256 with additional input",
        "keylen": 32,
        "entropy": "f45e9d040c1456f1c7f26e7f146469fbe3973007fe037239ad57623046e7ec52221b22eec208b22ac4cf4ca8d6253874",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "a75117ffcb5160486e91da8ed0af1a702d30703ab3631957aa19a7e3fc14714a",
        "expected_instantiate_v": "507b2124f5ae985e156db926a3230dfa",
        "generates": [
            {
                "additional_input": "28819bc79b92fc8790ebdc99812cdcea5c96e6feab32801ec1851b9f46e80eb6800028e61fbccb6ccbe42b06bf5a0864",
                "expected_key": "d75e41010982abd243b4d75642b86ce07e13b3652a3725aad011b1097c32957a",
                "expected_v": "939fbb584e0103982d2e73e05779849f",
                "returned_bits": None,
            },
            {
                "additional_input": "418ca848027e1b3c84d66717e6f31bf89684d5db94cd2d579233f716ac70ab66cc7b01a6f9ab8c7665fcc37dba4af1ad",
                "expected_key": "b0f80df4b33e5d2e3d72c8667ba9da1aa64a3a4936a3fdabf2c980d3104dfa13",
                "expected_v": "433abd3907feddce66cbcb216d5d833e",
                "returned_bits": "4f11406bd303c104243441a8f828bf0293cb20ac39392061429c3f56c1f426239f8f0c687b69897a2c7c8c2b4fb520b62741ffdd29f038b7c82a9d00a890a3ed",
            }
        ]
    }
]

reseed_test_vectors = [
    
    {
        "name": "CTR-DRBG AES-128 Reseed Test with no additional input",
        "keylen": 16,
        "initial_entropy": "ed1e7f21ef66ea5d8e2a85b9337245445b71d6393a4eecb0e63c193d0f72f9a9",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "b5fc83ef1518da3cb85598ee9795001e",
        "expected_instantiate_v": "58f90cf75af84f221514db847ec007d1",
        "reseed": {
            "entropy_input": "303fb519f0a4e17d6df0b6426aa0ecb2a36079bd48be47ad2a8dbfe48da3efad",
            "additional_input": "",
            "expected_key": "577a79cc512258c3e255fcf3f4cf0c1a",
            "expected_v": "531599fd616f33678192928bf771bb2b",
        },
        "generates": [
            {
                "additional_input": "",
                "expected_key": "ac373fb3773597b0d6cb6f37e6b59293",
                "expected_v": "cd9bf115d35c60cbf7f2ebac8e43f53b",
                "returned_bits": None,
            },
            {
                "additional_input": "",
                "expected_key": "964c57946a104aa93fc3c2137bb9bc11",
                "expected_v": "9d58008033ac007c9ead254bfa8de2b6",
                "returned_bits": "f80111d08e874672f32f42997133a5210f7a9375e22cea70587f9cfafebe0f6a6aa2eb68e7dd9164536d53fa020fcab20f54caddfab7d6d91e5ffec1dfd8deaa"
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-128 Reseed Test with additional input",
        "keylen": 16,
        "initial_entropy": "6bc709aa4c975b0eccb922ce2110fa9b572403f9013dfd10f06a88d54d380002",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "3325f564b6e96b6ffac63f9985f7bfc1",
        "expected_instantiate_v": "54acd937618b5e8203424a6c3c8afe7a",
        "reseed": {
            "entropy_input": "cf1af84eddd5bef666ea42bea6067a23e52742e24661f944ba2514fe052abf31",
            "additional_input": "a46988bad49b78c613c94e06a53b080bf6d20b7385bf4c782ad7cd145ddc9053",
            "expected_key": "b019e77ceda44835eb62b54297e622bc",
            "expected_v": "2712d648b6cfe3474d36a5c979e108c5",
        },
        "generates": [
            {
                "additional_input": "139d6f72bf1d0ec5bfdd245e013f5cdac85e3eca716196018b92133c00a07436",
                "expected_key": "274571de01ea976675e5afa85ef4e8d8",
                "expected_v": "ad64c20eb3d12084c732566de8aeb413",
                "returned_bits": None,
            },
            {
                "additional_input": "240f1a5af7fc2e4d32ace635acba5947f3564ecbfd7516c479c0adda20747f26",
                "expected_key": "6b8f6e05618974e281af1b2c9b53ec07",
                "expected_v": "61c3273f13468ee625800d99a1db46f3",
                "returned_bits": "e727268a546c0c891cf53a70a92820ee9bbf728ad52f30625b2e28f0f6c906f60ffd02f7d81623295950c04b63a48634eb41a5b4d649bdabff335ac3200690b0"
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-192 Reseed Test with no additional input",
        "keylen": 24,
        "initial_entropy": "d6e18f4565fdf2826d0d56419647c020413b963299d8de2c6510277f8ce988a7f0b3bc1df85b153f",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "1bd23dcfa28e05c9cd0387b28410e415d9dcb24e9e28206d",
        "expected_instantiate_v": "7936593c08597ea7da872ffb9a6efb58",
        "reseed": {
            "entropy_input": "a823d6311f9f66df329e3d7065e24fe2507e6b9dbcc22838483fa729ca5116d03a91028139d7130a",
            "additional_input": "",
            "expected_key": "f3b4059a6577ec2d43e04dae0f612efca23a65f027f24673",
            "expected_v": "c0a144bfb8f44bff8e5795b029272644",
        },
        "generates": [
            {
                "additional_input": "",
                "expected_key": "3885fa524d806d1388addacb250996359691771d5adfb589",
                "expected_v": "958939b869ceb68e2b63cf8783e18e69",
                "returned_bits": None,
            },
            {
                "additional_input": "",
                "expected_key": "0431726e0331e8ea97e2378de149ca2afd3bb92f082ea067",
                "expected_v": "952919d1ce84b84bb69abfa056fc41ea",
                "returned_bits": "4bf806690af13dbcfd448c79a3532e000bcabcef36f2643f3e1c9de607104282f81cd6cdcf8da8429c94108245114d3da17b9f48bb07094c073a94f5d2ef9e30"
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-192 Reseed Test with additional input",
        "keylen": 24,
        "initial_entropy": "658a2df4d2e371a9a97192869f77ca77abc80e3f6d2e1e295d4d228de2ac90d54d6cbefa2e9ba3da",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "a8b99f7e159086e2097f43758d20ee42332f2a436adee068",
        "expected_instantiate_v": "416b5cce661c66d567582d1c4cae4dbd",
        "reseed": {
            "entropy_input": "79fba3e14d225b26e6365bd1ae1649ae93d716dc09ed509bbe338e2c78883c77aa0f43aed3c2bb2d",
            "additional_input": "def5512314c47a6bb7cacb3529a66164ea48826650a54a6d9be9f5ee4fbb8c7d742d3deb005e8996",
            "expected_key": "b4cb27846240a5e63417acf06ecc920718ba359ee1d37180",
            "expected_v": "20cecf7a5821e13e09e6e0c89b6cd25f",
        },
        "generates": [
            {
                "additional_input": "54e3ad6f72c1f740a019572b7e446ad158e0a29bb0efbea60ff6f16596afbbcecfd35e65635f9f77",
                "expected_key": "b960d64d4bf2e24aa3a5da0033024884a06931d497fbd6d4",
                "expected_v": "be6c5e9d8b4a939aaa1bbeeef7bd72a9",
                "returned_bits": None,
            },
            {
                "additional_input": "6516e17a295d2fc141d2e8706e73822efd7b597fc576a97f43816cd1a9df4b9ff691324e2b581777",
                "expected_key": "4a8d68ff938f7c73bb5481104522cc1ec803f4133b10f116",
                "expected_v": "ba2a8f9dfd2b5909771506e5565b2374",
                "returned_bits": "932e59d41455f89ac8903019a683d5356894f4ad608f046f635779d3ae12e552aa75575c7bbfdeb59d253893b96f71538fec6047582eb9388379ad939c85c956"
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-256 Reseed Test with no additional input",
        "keylen": 32,
        "initial_entropy": "e4bc23c5089a19d86f4119cb3fa08c0a4991e0a1def17e101e4c14d9c323460a7c2fb58e0b086c6c57b55f56cae25bad",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "b7b3a93ecfdf2f61c622ad3afb6bff818736a09c9391157e1902d10a79d0db12",
        "expected_instantiate_v": "0e4fb6443cae46188617aad8bfe46e23",
        "reseed": {
            "entropy_input": "fd85a836bba85019881e8c6bad23c9061adc75477659acaea8e4a01dfe07a1832dad1c136f59d70f8653a5dc118663d6",
            "additional_input": "",
            "expected_key": "d230044c2594510d195ffe9923de8848bdbd19f24d0e7558b28e55b2d4de7841",
            "expected_v": "e18637ff12f514f37adc2013a40f38c1",
        },
        "generates": [
            {
                "additional_input": "",
                "expected_key": "ec871bb7a4f2c45dccdd0e514a21628959aa21e9643934f619b2709b3e38697c",
                "expected_v": "d8bbe7bfc60bfb710f39acd1088c9f41",
                "returned_bits": None,
            },
            {
                "additional_input": "",
                "expected_key": "e728308a0e92cbacb269d12246d8e2d24cf5fcc678aa09564132e4972c456eda",
                "expected_v": "c95f38da34ecb65ebf8b34c32bc215a5",
                "returned_bits": "b2cb8905c05e5950ca31895096be29ea3d5a3b82b269495554eb80fe07de43e193b9e7c3ece73b80e062b1c1f68202fbb1c52a040ea2478864295282234aaada"
            }
        ]
    },
    {
        "name": "CTR-DRBG AES-256 Reseed Test with additional input",
        "keylen": 32,
        "initial_entropy": "99903165903fea49c2db26ed675e44cc14cb2c1f28b836b203240b02771e831146ffc4335373bb344688c5c950670291",
        "nonce": "",
        "personalization": "",
        "expected_instantiate_key": "ca9fbb9e577adcf06bb8921ca3953747da6c6c2265d85ddc046aced1cded1e09",
        "expected_instantiate_v": "349fc7f964d59140972a30472561371f",
        "reseed": {
            "entropy_input": "b4ee99fa9e0eddaf4a3612013cd636c4af69177b43eebb3c58a305b9979b68b5cc820504f6c029aad78a5d29c66e84a0",
            "additional_input": "2d8c5c28b05696e74774eb69a10f01c5fabc62691ddf7848a8004bb5eeb4d2c5febe1aa01f4d557b23d7e9a0e4e90655",
            "expected_key": "a818a7727503bbc12d1ec0d849c668961695cf239a94629c35edaa3a0dc34091",
            "expected_v": "6497808af061e880ca7590236dc14219",
        },
        "generates": [
            {
                "additional_input": "0dc9cde42ac6e856f01a55f219c614de90c659260948db5053d414bab0ec2e13e995120c3eb5aafc25dc4bdcef8ace24",
                "expected_key": "b8f789ae947621954b718e26d184d24fc87f84b7b2cb418f57fd8d631987f2f1",
                "expected_v": "3186c69865342360696fd329978085b0",
                "returned_bits": None,
            },
            {
                "additional_input": "711be6c035013189f362211889248ca8a3268e63a7eb26836d915810a680ac4a33cd1180811a31a0f44f08db3dd64f91",
                "expected_key": "9b8d0688b357dfa9e18d6b5d4e1930cfe1556033bfcd19b3b43cefe0bb799f36",
                "expected_v": "6f339e91eb616432b39b5a4106f87019",
                "returned_bits": "11c7a0326ea737baa7a993d510fafee5374e7bbe17ef0e3e29f50fa68aac2124b017d449768491cac06d136d691a4e80785739f9aaedf311bba752a3268cc531"
            }
        ]
    }
]

def run_vector(tv):
    print(f"\nTesting: {tv['name']}")
    keylen = tv["keylen"]
    entropy = to_bytes(tv["entropy"])
    nonce = to_bytes(tv["nonce"])
    personalization = to_bytes(tv["personalization"])
    seed_material = entropy + nonce + personalization

    Key = b'\x00' * keylen
    V = b'\x00' * 16

    Key, V = drbg_update(seed_material, Key, V, keylen, do_xor=True)
    print("Instantiate:")
    print(" Key =", Key.hex(), "(expected:", tv['expected_instantiate_key'] + ")")
    print(" V   =", V.hex(),   "(expected:", tv['expected_instantiate_v']   + ")")
    if tv['expected_instantiate_key']:
        assert Key.hex() == tv['expected_instantiate_key'], "Instantiate Key mismatch"
    if tv['expected_instantiate_v']:
        assert V.hex() == tv['expected_instantiate_v'], "Instantiate V mismatch"

    for i, gen in enumerate(tv["generates"]):
        additional_input = to_bytes(gen["additional_input"])
        returned_bits, Key, V = drbg_generate(Key, V, 64, keylen, additional_input)

        print(f"Generate call {i+1}:")
        print(" Key =", Key.hex(), "(expected:", gen['expected_key'] + ")")
        print(" V   =", V.hex(),   "(expected:", gen['expected_v']   + ")")
        if gen["expected_key"]:
            assert Key.hex() == gen['expected_key'], f"Key mismatch (call {i+1})"
        if gen["expected_v"]:
            assert V.hex() == gen['expected_v'], f"V mismatch (call {i+1})"
        if gen["returned_bits"]:
            print(" ReturnedBits =", returned_bits.hex())
            print(" Expected     =", gen["returned_bits"])
            assert returned_bits.hex() == gen["returned_bits"], f"ReturnedBits mismatch (call {i+1})"

def run_reseed_vector(tv):
    print(f"\nTesting Reseed: {tv['name']}")
    keylen = tv["keylen"]
    entropy = to_bytes(tv["initial_entropy"])
    nonce = to_bytes(tv["nonce"])
    personalization = to_bytes(tv["personalization"])
    seed_material = entropy + nonce + personalization

    Key = b'\x00' * keylen
    V = b'\x00' * 16

    Key, V = drbg_update(seed_material, Key, V, keylen, do_xor=True)
    print("Instantiate:")
    print(" Key =", Key.hex(), "(expected:", tv['expected_instantiate_key'] + ")")
    print(" V   =", V.hex(),   "(expected:", tv['expected_instantiate_v']   + ")")
    if tv['expected_instantiate_key']:
        assert Key.hex() == tv['expected_instantiate_key'], "Instantiate Key mismatch"
    if tv['expected_instantiate_v']:
        assert V.hex() == tv['expected_instantiate_v'], "Instantiate V mismatch"

    reseed_entropy = to_bytes(tv["reseed"]["entropy_input"])
    reseed_additional = to_bytes(tv["reseed"]["additional_input"])
    
    print(" Reseed:")
    print(" Entropy Input =", reseed_entropy.hex() if reseed_entropy else "(empty)")
    print(" Additional Input =", reseed_additional.hex() if reseed_additional else "(empty)")
    
    Key, V = drbg_reseed(reseed_entropy, reseed_additional, Key, V, keylen)
    
    print("After reseed:")
    print(" Key =", Key.hex(), "(expected:", tv["reseed"]['expected_key'] + ")")
    print(" V   =", V.hex(),   "(expected:", tv["reseed"]['expected_v']   + ")")
    if tv["reseed"]['expected_key']:
        assert Key.hex() == tv["reseed"]['expected_key'], "Reseed Key mismatch"
    if tv["reseed"]['expected_v']:
        assert V.hex() == tv["reseed"]['expected_v'], "Reseed V mismatch"

    for i, gen in enumerate(tv["generates"]):
        additional_input = to_bytes(gen["additional_input"])
        returned_bits, Key, V = drbg_generate(Key, V, 64, keylen, additional_input)

        print(f"Generate call {i+1}:")
        print(" Key =", Key.hex(), "(expected:", gen['expected_key'] + ")")
        print(" V   =", V.hex(),   "(expected:", gen['expected_v']   + ")")
        if gen["expected_key"]:
            assert Key.hex() == gen['expected_key'], f"Generate Key mismatch (call {i+1})"
        if gen["expected_v"]:
            assert V.hex() == gen['expected_v'], f"Generate V mismatch (call {i+1})"
        if gen.get("returned_bits"):
            print(" ReturnedBits =", returned_bits.hex())
            print(" Expected     =", gen["returned_bits"])
            assert returned_bits.hex() == gen["returned_bits"], f"ReturnedBits mismatch (call {i+1})"

print("\nNORMAL TEST VECTORS")

for vector in test_vectors:
    try:
        run_vector(vector)
        print("\nPass")
    except AssertionError as e:
        print("\nFail", e)


print("\nRESEED TEST VCETORS")


for vector in reseed_test_vectors:
    try:
        run_reseed_vector(vector)
        print("\nPass")
    except AssertionError as e:
        print("\nFail", e)


print("Example with reseed")


def example_drbg():
    # Initialize DRBG
    keylen = 16  # 16 for AES-128, 24 for 192 and 32 for 256
    initial_entropy = bytes.fromhex("ce50f33da5d4c1d3d4004eb35244b7f2cd7f2e5076fbf6780a7ff634b249a5fc")
    nonce = b""
    personalization = b""
    
    Key = b'\x00' * keylen
    V = b'\x00' * 16
    
    # Instantiate
    seed_material = initial_entropy + nonce + personalization
    Key, V = drbg_update(seed_material, Key, V, keylen, do_xor=True)
    print("Initial state after instantiation:")
    print(f" Key: {Key.hex()}")
    print(f" V:   {V.hex()}")
    
    # Generate some random bytes
    random_bytes, Key, V = drbg_generate(Key, V, 32, keylen)
    print(f"\nGenerated 32 random bytes: {random_bytes.hex()}")
    print(f"State after generation:")
    print(f" Key: {Key.hex()}")
    print(f" V:   {V.hex()}")
    
    # Reseed with new entropy
    new_entropy = bytes.fromhex("1234567890abcdef" * 4) 
    additional_input = b"reseed_additional_data"
    Key, V = drbg_reseed(new_entropy, additional_input, Key, V, keylen)
    print(f"\nState after reseed:")
    print(f" Key: {Key.hex()}")
    print(f" V:   {V.hex()}")
    
    # Generate more random bytes after reseed
    random_bytes2, Key, V = drbg_generate(Key, V, 32, keylen)
    print(f"\nGenerated 32 random bytes after reseed: {random_bytes2.hex()}")
    print(f"Final state:")
    print(f" Key: {Key.hex()}")
    print(f" V:   {V.hex()}")

#example_usage()