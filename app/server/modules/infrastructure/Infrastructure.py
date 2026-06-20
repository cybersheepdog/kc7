# Import internal modules
from app.server.models import Base
import random
from app import db
from app.server.modules.helpers.word_generator import WordGenerator

# Import external modules
from faker import Faker
from faker.providers import internet

# Instantiate objects
fake = Faker()
fake.add_provider(internet)

wordGenerator = WordGenerator()


class Domain(Base):
    """ 
    Belongs to an actor
    There should be default actor to own non-malicious infrastructure
    """

    name              = db.Column(db.String(50))

    actor_id            = db.Column(db.Integer, db.ForeignKey('actor.id'))
    actor               = db.relationship('Actor', backref=db.backref('domains', lazy='dynamic'))

    def __init__(self, actor): 
        self.actor = actor
        self.name =  self._get_domain_name()
        


    def _get_domain_name(self) -> str:
        """
        Assemble a domain name using the list of theme words from the Actor object
        """
        from app.server.game_functions import LEGIT_DOMAINS

        separators = ["","-" ]
        tlds = self.actor.tld_values
        
        # if actor is default, let's get a larger list of randomised words
        if self.actor.is_default_actor:
            return random.choice(LEGIT_DOMAINS)
        else:
            # Splitting string representation of list from db into actual list
            domain_themes = self.actor.domain_theme_values
        domain_depth = self.actor.domain_depth or random.randint(1,2)
        words = random.choices(domain_themes, k=domain_depth)
        # THIS IS A HACK! You can optionally provide a list of domains (rather than theme words) in the actor config under 'domain_themes"
        if domain_depth == 1 and "." in words[0]:
            domain = random.choice(separators).join(list(set(words)))
        # This is the normal behavior (ie theme_word.tld)
        else:
            domain = random.choice(separators).join(list(set(words))) + "." + random.choice(tlds)

        return domain

class IP(Base):
    """ 
    Belongs to an actor
    There should be default actor to own non-malicious infrastructure
    """
    address             = db.Column(db.String(50), unique=True)              #next figure out how to have actors steal this
    actor_id            = db.Column(db.Integer, db.ForeignKey('actor.id'))
    actor               = db.relationship('Actor', backref=db.backref('ips', lazy='dynamic'))

    def __init__(self, actor):
        self.actor = actor
        self.address = self._generate_address(actor)

    @staticmethod
    def _generate_address(actor) -> str:
        """
        Address for this IP. When INFRA_REUSE_ENABLED is on (and this is a non-default
        actor that generates infrastructure), draw from the actor's stable "owned"
        network ranges so its IPs cluster recognizably across campaigns (#44). Otherwise
        — and on any error — fall back to the original fully-random public address, so
        default behavior is unchanged.
        """
        try:
            from flask import current_app
            if (not actor.is_default_actor
                    and getattr(actor, "generates_infrastructure", True)
                    and current_app.config.get("INFRA_REUSE_ENABLED")):
                from app.server.modules.infrastructure.infra_reuse import actor_ip_address
                addr = actor_ip_address(actor)
                if addr:
                    return addr
        except Exception:
            pass
        return fake.ipv4_public()