import random

def mutate_attack(attack):
    if "version" in attack:
        attack["version"] = attack["version"] + ".1"
    if "fake_hash" in attack:
        attack["fake_hash"] = attack["fake_hash"][:30]
    attack["mutation_level"] = random.randint(1,5)
    return attack