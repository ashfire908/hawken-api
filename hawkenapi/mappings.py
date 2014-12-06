# -*- coding: utf-8 -*-
# API mappings
# Copyright (c) 2013-2014 Andrew Hampe

from enum import IntEnum, unique


@unique
class MatchState(IntEnum):
    unavailable = 0
    prematch = 1
    inprogress = 2
    postmatch = 3


@unique
class InventoryItem(IntEnum):
    mech = 0
    paint_job = 1
    mech_a_part_upper = 2
    mech_a_part_middle = 3
    mech_a_part_arm = 4
    mech_a_part_lower = 5
    mech_a_part_booster = 6
    mech_a_part_armor = 7
    mech_b_part_upper = 8
    mech_b_part_middle = 9
    mech_b_part_arm = 10
    mech_b_part_lower = 11
    mech_b_part_booster = 12
    mech_b_part_armor = 13
    mech_c_part_upper = 14
    mech_c_part_middle = 15
    mech_c_part_arm = 16
    mech_c_part_lower = 17
    mech_c_part_booster = 18
    mech_c_part_armor = 19
    primary_weapon = 20
    secondary_weapon = 21
    item = 22
    # unused = 23
    consumable_triggered = 24
    consumable_passive = 25
    # unused = 26
    internals = 27
    upgrade_primary_weapon = 28
    upgrade_alt_weapon = 29
    upgrade_prestige_weapon = 30
    upgrade_secondary_weapon = 31
    upgrade_ability = 32
    healing_drone = 33
    ability = 34
    xp_boost = 35
    hp_boost = 36
    holo_taunt = 37
    anim_taunt = 38
    consumable_holotaunt = 39
    player_data = 40
    globals = 41
    emblem = 42
    ui_callout = 43
    mech_tier_2 = 44
    mech_tier_3 = 45
    mech_tier_4 = 46
    mech_tier_5 = 47
    local_test_drive = 48
    unified_part_booster = 49
    game_challenge = 50
    cockpit_decoration = 51
    primary_reticle = 52
    secondary_reticle = 53
    hud_color = 54
    server_region = 55
    private_server_token = 56


@unique
class Ability(IntEnum):
    none = 0
    cammo = 1
    attack_boost = 2
    coolant = 3
    fuel_replenish = 4
    barrier = 5
    overclock = 6
    heavy_turret = 7
    heavy_regen = 8
    heavy_mobile = 9
    heavy_vanguard = 10
    precision_overdrive = 11
    power_shot = 12
    mortar_cannon = 13
    amplification = 14
    magnetic_shell = 15
    stalker = 16
    bulwark = 17
    g2_coolant = 18
    g2_cammo = 19
    g2_speed_boost = 20
    g2_power_shot = 21
    heat_wave = 22
    siege_tank = 23
    g2_attack_boost = 24
    g2_healing_blast = 25


@unique
class Mech(IntEnum):
    type_a_berserker = 0
    type_a_infiltrator = 1
    type_b_raider = 2
    type_a_sniper = 3
    type_a_technician = 4
    type_b_bruiser = 5
    # unused = 6
    # unused = 7
    type_b_sharpshooter = 8
    type_c_brawler = 9
    # unused = 10
    type_c_rocketeer = 11
    type_a_scout = 12
    type_c_grenadier = 13
    type_b_assault = 14
    type_b_rookie = 15
    type_c_vanguard = 16
    type_b_predator = 17
    # unused = 18
    # unused = 19
    type_c_g2_raider = 20
    type_c_vanguard_2 = 21
    type_b_g2_assault = 22
    # unused = 23
    type_c_firefighter = 24
    # unused = 25
    type_a_g2_berserker = 26
    type_c_brawler_bossmode = 27
